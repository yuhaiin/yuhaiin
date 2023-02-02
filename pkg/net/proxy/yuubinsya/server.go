package yuubinsya

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
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
	addr     string
	password []byte

	cert, key []byte

	Lis net.Listener

	mac ed25519.PrivateKey
}

func NewServer(host, password string, certPEM, keyPEM []byte) (*yuubinsya, error) {
	y := &yuubinsya{
		addr:     host,
		password: []byte(password),
		cert:     certPEM,
		key:      keyPEM,
	}
	y.mac = ed25519.NewKeyFromSeed(kdf(y.password, ed25519.SeedSize))

	return y, nil

}

func (y *yuubinsya) Start() error {
	lis, err := net.Listen("tcp", y.addr)
	if err != nil {
		return err
	}

	log.Println("new server listen at:", lis.Addr())

	var tlsConfig *tls.Config

	if y.cert != nil && y.key != nil {
		cert, err := tls.X509KeyPair(y.cert, y.key)
		if err != nil {
			return err
		}

		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
		}
	}

	for {
		conn, err := lis.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return err
			}

			continue
		}

		conn.(*net.TCPConn).SetKeepAlive(true)

		if tlsConfig != nil {
			conn = tls.Server(conn, tlsConfig)
		} else {
			con, err := handshakeServer(conn, y.mac)
			if err != nil {
				conn.Close()
				log.Println("handshake failed:", err)
				continue
			}

			conn = con
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

	z := make([]byte, 2) // net
	if _, err := io.ReadFull(c, z); err != nil {
		return err
	}

	if z[0] != tcp && z[0] != udp {
		return errors.New("unknown network")
	}

	if z[1] > 0 {
		password := make([]byte, z[1])
		if _, err := io.ReadFull(c, password); err != nil {
			return err
		}

		if !bytes.Equal(password, y.password) {
			return errors.New("password is incorrect")
		}
	}

	switch z[0] {
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
	log.Println("new udp connect from", c.RemoteAddr())

	packetConn, err := net.ListenPacket("udp", "")
	if err != nil {
		return err
	}
	defer packetConn.Close()

	go func() {
		buf := pool.GetBytes(MaxPacketSize)
		defer pool.PutBytes(buf)
		buffer := pool.GetBuffer()
		defer pool.PutBuffer(buffer)

		for {
			packetConn.SetReadDeadline(time.Now().Add(time.Minute))
			n, from, err := packetConn.ReadFrom(buf)
			if err != nil {
				return
			}

			buffer.Reset()

			addr, err := proxy.ParseSysAddr(from)
			if err != nil {
				return
			}

			s5c.ParseAddrWriter(addr, buffer)
			if err = binary.Write(buffer, binary.BigEndian, uint16(n)); err != nil {
				return
			}
			buffer.Write(buf[:n])

			if _, err := c.Write(buffer.Bytes()); err != nil {
				return
			}
		}
	}()

	var length uint16

	for {
		addr, err := s5c.ResolveAddr(c)
		if err != nil {
			return err
		}

		if err = binary.Read(c, binary.BigEndian, &length); err != nil {
			return err
		}

		buf := pool.GetBytesV2(int(length))

		if _, err = io.ReadFull(c, buf.Bytes()); err != nil {
			return err
		}

		paddr := addr.Address(statistic.Type_udp)

		udpAddr, err := paddr.UDPAddr()
		if err != nil {
			return err
		}
		if _, err = packetConn.WriteTo(buf.Bytes(), udpAddr); err != nil {
			return err
		}

		pool.PutBytesV2(buf)
	}
}

func kdf(password []byte, keyLen int) []byte {
	var b, prev []byte
	h := sha256.New()
	for len(b) < keyLen {
		h.Write(prev)
		h.Write(password)
		b = h.Sum(b)
		prev = b[len(b)-h.Size():]
		h.Reset()
	}
	return b[:keyLen]
}
