package websocket

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"
	"github.com/gorilla/websocket"
)

type Client struct {
	uri    string
	header http.Header
	dialer websocket.Dialer
	p      proxy.Proxy
}

func NewWebsocket(host, path string, insecureSkipVerify, tlsEnable bool, tlsCaCertFilePath []string) func(p proxy.Proxy) (proxy.Proxy, error) {
	return func(p proxy.Proxy) (proxy.Proxy, error) {
		c := &Client{p: p}

		c.dialer = websocket.Dialer{
			NetDial: func(network, addr string) (net.Conn, error) {
				return p.Conn(addr)
			},
			// ReadBufferSize:   16 * 1024,
			// WriteBufferSize:  16 * 1024,
			HandshakeTimeout: time.Second * 12,
		}

		protocol := "ws"
		if tlsEnable {
			//tls
			protocol = "wss"
			root, err := x509.SystemCertPool()
			if err != nil {
				log.Printf("get x509 system cert pool failed: %v, create new cert pool.", err)
				root = x509.NewCertPool()
			}

			ns, _, err := net.SplitHostPort(host)
			if err != nil {
				log.Printf("split host and port failed: %v", err)
				ns = host
			}
			c.dialer.TLSClientConfig = &tls.Config{
				ServerName:             ns,
				RootCAs:                root,
				NextProtos:             []string{"http/1.1"},
				InsecureSkipVerify:     insecureSkipVerify,
				SessionTicketsDisabled: true,
				ClientSessionCache:     tlsSessionCache,
			}

			for i := range tlsCaCertFilePath {
				if tlsCaCertFilePath[i] == "" {
					continue
				}

				cert, err := ioutil.ReadFile(tlsCaCertFilePath[i])
				if err != nil {
					log.Printf("read cert failed: %v\n", err)
					continue
				}

				ok := c.dialer.TLSClientConfig.RootCAs.AppendCertsFromPEM(cert)
				if !ok {
					log.Printf("add cert from pem failed.")
				}
			}
		}

		c.header = http.Header{}
		c.header.Add("Host", host)
		c.uri = fmt.Sprintf("%s://%s%s", protocol, host, getNormalizedPath(path))

		return c, nil
	}
}

func (c *Client) Conn(string) (net.Conn, error) {
	con, _, err := c.dialer.Dial(c.uri, c.header)
	if err != nil {
		return nil, fmt.Errorf("websocket dial failed: %w", err)
	}
	return &wsConn{Conn: con}, nil
}

func (c *Client) PacketConn(host string) (net.PacketConn, error) {
	return c.p.PacketConn(host)
}

var tlsSessionCache = tls.NewLRUClientSessionCache(128)

func getNormalizedPath(path string) string {
	if path == "" {
		return "/"
	}
	if path[0] != '/' {
		return "/" + path
	}
	return path
}

var _ net.Conn = (*wsConn)(nil)

type wsConn struct {
	*websocket.Conn
	reader io.Reader
}

func (w *wsConn) Read(b []byte) (int, error) {
	for {
		reader, err := w.getReader()
		if err != nil {
			return 0, err
		}

		nBytes, err := reader.Read(b)
		if err != nil && errors.Is(err, io.EOF) {
			w.reader = nil
			continue
		}
		return nBytes, err
	}
}

func (w *wsConn) Write(b []byte) (int, error) {
	err := w.Conn.WriteMessage(websocket.BinaryMessage, b)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (w *wsConn) getReader() (io.Reader, error) {
	if w.reader != nil {
		return w.reader, nil
	}

	_, reader, err := w.Conn.NextReader()
	if err != nil {
		return nil, err
	}
	w.reader = reader
	return reader, nil
}

func (w *wsConn) SetDeadline(t time.Time) error {
	err := w.Conn.SetReadDeadline(t)
	if err != nil {
		return err
	}
	return w.Conn.SetWriteDeadline(t)
}
