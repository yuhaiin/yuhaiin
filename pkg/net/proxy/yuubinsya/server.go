package yuubinsya

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/nat"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/quic"
	s5c "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/client"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/yuubinsya/entity"
	pl "github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	quicgo "github.com/quic-go/quic-go"
)

type server struct {
	Listener   net.Listener
	handshaker entity.Handshaker

	ctx    context.Context
	cancel context.CancelFunc

	tcpChannel chan *netapi.StreamMeta
	udpChannel chan *netapi.Packet
}

func init() {
	pl.RegisterProtocol2(NewServer)
}

func NewServer(config *pl.Inbound_Yuubinsya) func(pl.InboundI) (netapi.ProtocolServer, error) {

	return func(ii pl.InboundI) (netapi.ProtocolServer, error) {
		ctx, cancel := context.WithCancel(context.TODO())
		s := &server{
			Listener:   ii,
			handshaker: NewHandshaker(!config.Yuubinsya.ForceDisableEncrypt, []byte(config.Yuubinsya.Password)),
			ctx:        ctx,
			cancel:     cancel,
			tcpChannel: make(chan *netapi.StreamMeta, 100),
			udpChannel: make(chan *netapi.Packet, 100),
		}

		go func() {
			if err := s.Start(); err != nil {
				log.Error("yuubinsya server failed:", "err", err)
			}
		}()

		return s, nil
	}
}

func (y *server) Start() (err error) {
	log.Info("new yuubinsya server", "host", y.Listener.Addr())

	for {
		conn, err := y.Listener.Accept()
		if err != nil {
			log.Error("accept failed", "err", err)
			return err
		}

		go func() {
			if err := y.handle(conn); err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, os.ErrDeadlineExceeded) {
				log.Error("handle failed", slog.Any("from", conn.RemoteAddr()), slog.Any("err", err))
			}
		}()
	}
}

func (y *server) handle(conn net.Conn) error {
	c, err := y.handshaker.HandshakeServer(conn)
	if err != nil {
		return fmt.Errorf("handshake failed: %w", err)
	}

	net, err := y.handshaker.ParseHeader(c)
	if err != nil {
		write403(conn)
		return fmt.Errorf("parse header failed: %w", err)
	}

	switch net {
	case entity.TCP:
		target, err := s5c.ResolveAddr(c)
		if err != nil {
			return fmt.Errorf("resolve addr failed: %w", err)
		}

		addr := target.Address(statistic.Type_tcp)

		select {
		case <-y.ctx.Done():
			return y.ctx.Err()
		case y.tcpChannel <- &netapi.StreamMeta{
			Source:      c.RemoteAddr(),
			Destination: addr,
			Inbound:     c.LocalAddr(),
			Src:         c,
			Address:     addr,
		}:
		}
	case entity.UDP:
		return func() error {
			defer c.Close()
			log.Debug("new udp connect", "from", c.RemoteAddr())
			for {
				if err := y.forwardPacket(c); err != nil {
					return fmt.Errorf("handle packet request failed: %w", err)
				}
			}
		}()
	}

	return nil
}

func (y *server) Close() error {
	if y.Listener == nil {
		return nil
	}
	return y.Listener.Close()
}

func (y *server) forwardPacket(c net.Conn) error {
	addr, err := s5c.ResolveAddr(c)
	if err != nil {
		return err
	}

	var length uint16
	if err := binary.Read(c, binary.BigEndian, &length); err != nil {
		return err
	}

	bufv2 := pool.GetBytesV2(length)

	if _, err = io.ReadFull(c, bufv2.Bytes()); err != nil {
		return err
	}

	src := c.RemoteAddr()
	if conn, ok := c.(interface{ StreamID() quicgo.StreamID }); ok {
		src = &quic.QuicAddr{Addr: c.RemoteAddr(), ID: conn.StreamID()}
	}

	select {
	case <-y.ctx.Done():
		return y.ctx.Err()
	case y.udpChannel <- &netapi.Packet{
		Src:     src,
		Dst:     addr.Address(statistic.Type_udp),
		Payload: bufv2,
		WriteBack: func(buf []byte, from net.Addr) (int, error) {
			addr, err := netapi.ParseSysAddr(from)
			if err != nil {
				return 0, err
			}

			s5Addr := s5c.ParseAddr(addr)

			buffer := pool.GetBytesV2(len(s5Addr) + 2 + nat.MaxSegmentSize)
			defer pool.PutBytesV2(buffer)

			copy(buffer.Bytes(), s5Addr)
			binary.BigEndian.PutUint16(buffer.Bytes()[len(s5Addr):], uint16(len(buf)))
			copy(buffer.Bytes()[len(s5Addr)+2:], buf)

			if _, err := c.Write(buffer.Bytes()[:len(s5Addr)+2+len(buf)]); err != nil {
				return 0, err
			}

			return len(buf), nil
		},
	}:
	}
	return nil
}

func (y *server) AcceptStream() (*netapi.StreamMeta, error) {
	select {
	case <-y.ctx.Done():
		return nil, y.ctx.Err()
	case meta := <-y.tcpChannel:
		return meta, nil
	}
}
func (y *server) AcceptPacket() (*netapi.Packet, error) {
	select {
	case <-y.ctx.Done():
		return nil, y.ctx.Err()
	case packet := <-y.udpChannel:
		return packet, nil
	}
}

func write403(conn net.Conn) {
	data := []byte(`<html>
<head><title>403 Forbidden</title></head>
<body>
<center><h1>403 Forbidden</h1></center>
<hr><center>openresty</center>
</body>
</html>`)
	t := http.Response{
		Status:        http.StatusText(http.StatusForbidden),
		StatusCode:    http.StatusForbidden,
		Body:          io.NopCloser(bytes.NewBuffer(data)),
		Header:        http.Header{},
		Proto:         "HTTP/2",
		ProtoMajor:    2,
		ProtoMinor:    2,
		ContentLength: int64(len(data)),
	}

	t.Header.Add("content-type", "text/html")
	t.Header.Add("date", time.Now().UTC().Format(time.RFC1123))
	t.Header.Add("server", "openresty")

	_ = t.Write(conn)
}
