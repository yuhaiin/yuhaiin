package quic

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"
	"github.com/lucas-clemente/quic-go"
)

type Client struct {
	addr       *net.UDPAddr
	tlsConfig  *tls.Config
	quicConfig *quic.Config
	p          proxy.Proxy
}

func NewClient(network, address string, port int, certPath []string, insecureSkipVerify bool) (*Client, error) {
	c := &Client{}
	var err error

	switch network {
	case "ip":
		var ip net.IP
		ip = net.ParseIP(address)
		if ip == nil {
			addrs, err := net.LookupAddr(address)
			if err != nil || len(addrs) == 0 {
				return nil, fmt.Errorf("look addr failed: %v", err)
			}
			ip = net.ParseIP(addrs[0])
			if ip == nil {
				return nil, fmt.Errorf("can't get ip")
			}
		}
		c.addr = &net.UDPAddr{IP: ip, Port: port}
	default:
		c.addr, err = net.ResolveUDPAddr("udp", address)
		if err != nil {
			return nil, err
		}
	}

	root, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("get system cert pool failed: %v", err)
	}

	ns, _, err := net.SplitHostPort(address)
	if err != nil {
		log.Printf("split host and port failed: %v", err)
		ns = address
	}
	c.tlsConfig = &tls.Config{
		RootCAs:                root,
		ServerName:             ns,
		SessionTicketsDisabled: true,
		NextProtos:             nil,
		InsecureSkipVerify:     insecureSkipVerify,
		ClientSessionCache:     tlsSessionCache,
	}

	for i := range certPath {
		if certPath[i] == "" {
			continue
		}
		cert, err := ioutil.ReadFile(certPath[i])
		if err != nil {
			log.Println(err)
			continue
		}

		ok := c.tlsConfig.RootCAs.AppendCertsFromPEM(cert)
		if !ok {
			log.Printf("add cert from pem failed.")
		}

		// block, _ := pem.Decode(cert)
		// if block == nil {
		// 	continue
		// }

		// certA, err := x509.ParseCertificate(block.Bytes)
		// if err != nil {
		// 	log.Printf("parse certificate failed: %v", err)
		// 	continue
		// }

		// tlsConfig.Certificates = append(
		// 	tlsConfig.Certificates,
		// 	tls.Certificate{
		// 		Certificate: [][]byte{certA.Raw},
		// 	},
		// )
		// tlsConfig.RootCAs.AddCert(certA)
	}

	c.quicConfig = &quic.Config{
		KeepAlive:            true,
		ConnectionIDLength:   12,
		HandshakeIdleTimeout: time.Second * 8,
		MaxIdleTimeout:       time.Second * 30,
	}

	return c, nil
}

func NewQUIC(serverName string, certPath []string, insecureSkipVerify bool) func(proxy.Proxy) (proxy.Proxy, error) {
	return func(p proxy.Proxy) (proxy.Proxy, error) {
		c := &Client{p: p}
		var err error

		root, err := x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("get system cert pool failed: %v", err)
		}

		c.tlsConfig = &tls.Config{
			RootCAs:                root,
			ServerName:             serverName,
			SessionTicketsDisabled: true,
			NextProtos:             nil,
			InsecureSkipVerify:     insecureSkipVerify,
			ClientSessionCache:     tlsSessionCache,
		}

		for i := range certPath {
			if certPath[i] == "" {
				continue
			}
			cert, err := ioutil.ReadFile(certPath[i])
			if err != nil {
				log.Println(err)
				continue
			}

			ok := c.tlsConfig.RootCAs.AppendCertsFromPEM(cert)
			if !ok {
				log.Printf("add cert from pem failed.")
			}

			// block, _ := pem.Decode(cert)
			// if block == nil {
			// 	continue
			// }

			// certA, err := x509.ParseCertificate(block.Bytes)
			// if err != nil {
			// 	log.Printf("parse certificate failed: %v", err)
			// 	continue
			// }

			// tlsConfig.Certificates = append(
			// 	tlsConfig.Certificates,
			// 	tls.Certificate{
			// 		Certificate: [][]byte{certA.Raw},
			// 	},
			// )
			// tlsConfig.RootCAs.AddCert(certA)
		}

		c.quicConfig = &quic.Config{
			KeepAlive:            true,
			ConnectionIDLength:   12,
			HandshakeIdleTimeout: time.Second * 8,
			MaxIdleTimeout:       time.Second * 30,
		}

		return c, nil
	}
}
func (c *Client) NewConn() (net.Conn, error) {
	conn, err := net.DialUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0}, c.addr)
	if err != nil {
		return nil, err
	}

	session, err := quic.DialContext(context.Background(), conn, c.addr, "", c.tlsConfig, c.quicConfig)
	if err != nil {
		return nil, err
	}

	stream, err := session.OpenStream()
	if err != nil {
		return nil, err
	}

	return &interConn{Stream: stream, local: session.LocalAddr(), remote: session.RemoteAddr()}, nil
}

func (c *Client) Conn(host string) (net.Conn, error) {
	conn, err := c.p.PacketConn(host)
	if err != nil {
		return nil, err
	}
	session, err := quic.DialContext(context.Background(), conn, c.addr, "", c.tlsConfig, c.quicConfig)
	if err != nil {
		return nil, err
	}

	stream, err := session.OpenStream()
	if err != nil {
		return nil, err
	}

	return &interConn{Stream: stream, local: session.LocalAddr(), remote: session.RemoteAddr()}, nil
}

func (c *Client) PacketConn(host string) (net.PacketConn, error) {
	return c.p.PacketConn(host)
}

var tlsSessionCache = tls.NewLRUClientSessionCache(128)

var _ net.Conn = (*interConn)(nil)

type interConn struct {
	quic.Stream
	local  net.Addr
	remote net.Addr
}

func (c *interConn) LocalAddr() net.Addr {
	return c.local
}

func (c *interConn) RemoteAddr() net.Addr {
	return c.remote
}
