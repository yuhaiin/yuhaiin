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

	"github.com/lucas-clemente/quic-go"
)

var tlsSessionCache = tls.NewLRUClientSessionCache(128)

func QuicDial(network, address string, port int, certPath []string, insecureSkipVerify bool) (net.Conn, error) {
	var addr *net.UDPAddr
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
		addr = &net.UDPAddr{IP: ip, Port: port}
	default:
		addr, err = net.ResolveUDPAddr("udp", address)
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
	tlsConfig := &tls.Config{
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

		ok := tlsConfig.RootCAs.AppendCertsFromPEM(cert)
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

	quicConfig := &quic.Config{
		KeepAlive:          true,
		ConnectionIDLength: 12,
		HandshakeTimeout:   time.Second * 8,
		MaxIdleTimeout:     time.Second * 30,
	}

	conn, err := net.DialUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0}, addr)
	if err != nil {
		return nil, err
	}

	session, err := quic.DialContext(context.Background(), conn, addr, "", tlsConfig, quicConfig)
	if err != nil {
		return nil, err
	}

	stream, err := session.OpenStream()
	if err != nil {
		return nil, err
	}

	return &interConn{Stream: stream, local: session.LocalAddr(), remote: session.RemoteAddr()}, nil
}

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
