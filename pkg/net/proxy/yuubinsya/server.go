package yuubinsya

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	s5c "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/client"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"github.com/Asutorufa/yuhaiin/pkg/utils/relay"
)

const (
	MaxPacketSize = 1024 * 8
)

type yuubinsya struct {
	addr, serverName string
	password         []byte

	cert, key []byte

	Lis net.Listener
}

func NewServer(host, serverName, password string, certPEM, keyPEM []byte) (*yuubinsya, error) {
	y := &yuubinsya{
		addr:     host,
		password: []byte(password),
		cert:     certPEM,
		key:      keyPEM,
	}

	return y, nil

}

func (y *yuubinsya) Start() error {
	lis, err := net.Listen("tcp", y.addr)
	if err != nil {
		return err
	}

	log.Println("new server listen at:", lis.Addr())

	cert, err := tls.X509KeyPair(y.cert, y.key)
	if err != nil {
		return err
	}

	lis = tls.NewListener(lis, &tls.Config{
		ServerName:   y.serverName,
		Certificates: []tls.Certificate{cert},
	})

	for {
		conn, err := lis.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return err
			}

			continue
		}

		go func() {
			if err := y.handle(conn); err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.EOF) && !errors.Is(err, os.ErrDeadlineExceeded) {
				log.Println("handle failed:", err)
			}
		}()
	}
}

var (
	tcp byte = 66
	udp byte = 77
)

func (y *yuubinsya) handle(c net.Conn) error {
	defer c.Close()

	z := make([]byte, 1) // net
	if _, err := io.ReadFull(c, z); err != nil {
		return err
	}

	net := z[0]
	if net != tcp && net != udp {
		return errors.New("unknown network")
	}

	if _, err := io.ReadFull(c, z); err != nil {
		return err
	}

	password := make([]byte, z[0])
	if _, err := io.ReadFull(c, password); err != nil {
		return err
	}

	if !bytes.Equal(password, y.password) {
		return errors.New("password is incorrect")
	}

	switch net {
	case tcp:
		target, err := s5c.ResolveAddr(c)
		if err != nil {
			return err
		}
		return y.handleTCP(c, target)
	case udp:
		return y.handleUDP(c)
	}

	return nil
}

func (y *yuubinsya) handleTCP(c net.Conn, target s5c.ADDR) error {
	addr := target.Address(statistic.Type_tcp).String()

	log.Printf("new tcp connect from %v to %v\n", c.RemoteAddr(), addr)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	go relay.Copy(conn, c)
	relay.Copy(c, conn)
	return nil
}

func (y *yuubinsya) handleUDP(c net.Conn) error {
	packetConn, err := net.ListenPacket("udp", "")
	if err != nil {
		return err
	}
	defer packetConn.Close()

	go func() {
		buf := pool.GetBytes(MaxPacketSize)
		defer pool.PutBytes(buf)
		for {
			packetConn.SetReadDeadline(time.Now().Add(time.Minute))
			n, from, err := packetConn.ReadFrom(buf)
			if err != nil {
				return
			}

			addr, err := proxy.ParseSysAddr(from)
			if err != nil {
				return
			}

			s5c.ParseAddrWriter(addr, c)
			if err = binary.Write(c, binary.BigEndian, uint16(n)); err != nil {
				return
			}

			if _, err := c.Write(buf[:n]); err != nil {
				return
			}
		}
	}()

	for {
		addr, err := s5c.ResolveAddr(c)
		if err != nil {
			return err
		}

		var length uint16
		if err = binary.Read(c, binary.BigEndian, &length); err != nil {
			return err
		}

		buf := pool.GetBytesV2(int(length))

		if _, err = io.ReadFull(c, buf.Bytes()); err != nil {
			return err
		}

		paddr := addr.Address(statistic.Type_udp)

		log.Printf("new udp connect from %v to %v\n", c.RemoteAddr(), paddr)

		udpAddr, err := paddr.UDPAddr()
		if err != nil {
			return err
		}
		if _, err = packetConn.WriteTo(buf.Bytes(), udpAddr); err != nil {
			return err
		}
	}
}
