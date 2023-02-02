package yuubinsya

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	s5c "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/client"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"golang.org/x/crypto/chacha20poly1305"
)

func (c *Client) WriteHeader(conn net.Conn, cmd byte, addr proxy.Address) (err error) {
	buf := pool.GetBuffer()
	defer pool.PutBuffer(buf)

	buf.WriteByte(cmd)
	if c.tlsConfig != nil {
		buf.WriteByte(byte(len(c.password)))
		buf.Write(c.password)
	} else {
		buf.WriteByte(0)
	}

	if cmd == tcp {
		s5c.ParseAddrWriter(addr, buf)
	}
	_, err = conn.Write(buf.Bytes())
	return
}

func handshake(conn net.Conn, mac ed25519.PrivateKey) (net.Conn, error) {
	buf := pool.GetBytesV2(ed25519.SignatureSize + 65)
	defer pool.PutBytesV2(buf)

	pk, err := sendPublicKey(buf, conn, mac)
	if err != nil {
		return nil, err
	}

	rPub, err := getSenderPrivateKey(buf, conn, mac)
	if err != nil {
		return nil, err
	}

	cryptKey, err := pk.ECDH(rPub)
	if err != nil {
		return nil, err
	}

	aead, err := chacha20poly1305.New(kdf(cryptKey, chacha20poly1305.KeySize))
	if err != nil {
		return nil, err
	}

	return NewConn(conn, aead), nil
}

func handshakeServer(conn net.Conn, mac ed25519.PrivateKey) (net.Conn, error) {
	buf := pool.GetBytesV2(ed25519.SignatureSize + 65)
	defer pool.PutBytesV2(buf)

	rPub, err := getSenderPrivateKey(buf, conn, mac)
	if err != nil {
		return nil, err
	}

	pk, err := sendPublicKey(buf, conn, mac)
	if err != nil {
		return nil, err
	}

	cryptKey, err := pk.ECDH(rPub)
	if err != nil {
		return nil, err
	}

	aead, err := chacha20poly1305.New(kdf(cryptKey, chacha20poly1305.KeySize))
	if err != nil {
		return nil, err
	}

	return NewConn(conn, aead), nil
}

func getSenderPrivateKey(buf *pool.Bytes, conn net.Conn, mac ed25519.PrivateKey) (*ecdh.PublicKey, error) {
	if _, err := io.ReadFull(conn, buf.Bytes()); err != nil {
		return nil, err
	}

	rPubSignature := buf.Bytes()[:ed25519.SignatureSize]
	rPubBYtes := buf.Bytes()[ed25519.SignatureSize:]

	rSignature, err := mac.Sign(rand.Reader, rPubBYtes, crypto.Hash(0))
	if err != nil {
		return nil, err
	}

	if !bytes.Equal(rSignature, rPubSignature) {
		return nil, errors.New("can't verify pub signature")
	}

	return ecdh.P256().NewPublicKey(rPubBYtes)
}

func sendPublicKey(buf *pool.Bytes, conn net.Conn, mac ed25519.PrivateKey) (*ecdh.PrivateKey, error) {
	pk, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	pubBytes := pk.PublicKey().Bytes()
	pubSignature, err := mac.Sign(rand.Reader, pubBytes, crypto.Hash(0))
	if err != nil {
		return nil, err
	}

	copy(buf.Bytes(), pubSignature)
	copy(buf.Bytes()[ed25519.SignatureSize:], pubBytes)

	if _, err = conn.Write(buf.Bytes()); err != nil {
		return nil, err
	}
	return pk, nil
}

type Client struct {
	proxy     proxy.Proxy
	password  []byte
	tlsConfig *tls.Config
	compress  bool

	mac ed25519.PrivateKey
}

func New(config *protocol.Protocol_Yuubinsya) protocol.WrapProxy {
	return func(dialer proxy.Proxy) (proxy.Proxy, error) {
		c := &Client{
			password:  []byte(config.Yuubinsya.Password),
			proxy:     dialer,
			tlsConfig: protocol.ParseTLSConfig(config.Yuubinsya.Tls),
		}

		if c.tlsConfig != nil {
			c.tlsConfig.MinVersion = tls.VersionTLS13
		}

		c.mac = ed25519.NewKeyFromSeed(kdf(c.password, ed25519.SeedSize))

		return c, nil
	}
}

func (c *Client) conn(addr proxy.Address) (net.Conn, error) {
	conn, err := c.proxy.Conn(addr)
	if err != nil {
		return nil, err
	}

	if c.tlsConfig != nil {
		conn = tls.Client(conn, c.tlsConfig)
	} else {
		conn, err = handshake(conn, c.mac)

	}
	return conn, err
}

func (c *Client) Conn(addr proxy.Address) (net.Conn, error) {
	conn, err := c.conn(addr)
	if err != nil {
		return nil, err
	}

	if err = c.WriteHeader(conn, tcp, addr); err != nil {
		conn.Close()
		return nil, fmt.Errorf("write header failed: %w", err)
	}
	return conn, nil
}

func (c *Client) PacketConn(addr proxy.Address) (net.PacketConn, error) {
	conn, err := c.conn(addr)
	if err != nil {
		return nil, err
	}
	if err = c.WriteHeader(conn, udp, addr); err != nil {
		conn.Close()
		return nil, fmt.Errorf("write header failed: %w", err)
	}
	return &PacketConn{Conn: conn}, nil
}

type PacketConn struct {
	net.Conn

	remain int
	addr   proxy.Address
	rmux   sync.Mutex
	wmux   sync.Mutex
}

func (c *PacketConn) WriteTo(payload []byte, addr net.Addr) (int, error) {
	c.wmux.Lock()
	defer c.wmux.Unlock()

	taddr, err := proxy.ParseSysAddr(addr)
	if err != nil {
		return 0, fmt.Errorf("failed to parse addr: %w", err)
	}

	w := pool.GetBuffer()
	defer pool.PutBuffer(w)

	s5c.ParseAddrWriter(taddr, w)
	addrSize := w.Len()

	b := bytes.NewBuffer(payload)

	for b.Len() > 0 {
		data := b.Next(MaxPacketSize)

		w.Truncate(addrSize)

		binary.Write(w, binary.BigEndian, uint16(len(data)))

		w.Write(data)

		_, err = c.Conn.Write(w.Bytes())
		if err != nil {
			return len(payload) - b.Len() + len(data), fmt.Errorf("write to %v failed: %w", addr, err)
		}
	}

	return len(payload), nil
}

func (c *PacketConn) ReadFrom(payload []byte) (n int, _ net.Addr, err error) {
	c.rmux.Lock()
	defer c.rmux.Unlock()

	if c.remain > 0 {
		var z int
		if c.remain > len(payload) {
			z = len(payload)
		} else {
			z = c.remain
		}

		n, err := c.Conn.Read(payload[:z])
		if err != nil {
			return 0, c.addr, err
		}

		c.remain -= n
		return n, c.addr, err
	}

	addr, err := s5c.ResolveAddr(c.Conn)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to resolve udp packet addr: %w", err)
	}

	c.addr = addr.Address(statistic.Type_udp)

	var length uint16
	if err = binary.Read(c.Conn, binary.BigEndian, &length); err != nil {
		return 0, nil, fmt.Errorf("read length failed: %w", err)
	}
	if length > MaxPacketSize {
		return 0, nil, fmt.Errorf("invalid packet size")
	}

	plen := len(payload)
	if int(length) < plen {
		plen = int(length)
	} else {
		c.remain = int(length) - plen
	}

	n, err = io.ReadFull(c.Conn, payload[:plen])
	return n, c.addr, err
}
