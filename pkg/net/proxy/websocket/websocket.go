package websocket

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"
	nyws "nhooyr.io/websocket"
)

type Client struct {
	uri string
	p   proxy.Proxy

	dialOptions *nyws.DialOptions
}

func NewWebsocket(host, path string, insecureSkipVerify, tlsEnable bool, tlsCaCertFilePath []string) func(p proxy.Proxy) (proxy.Proxy, error) {
	return func(p proxy.Proxy) (proxy.Proxy, error) {
		c := &Client{p: p}

		transport := &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return p.Conn(addr)
			},
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
			transport.TLSClientConfig = &tls.Config{
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

				ok := transport.TLSClientConfig.RootCAs.AppendCertsFromPEM(cert)
				if !ok {
					log.Printf("add cert from pem failed.")
				}
			}
		}

		c.dialOptions = &nyws.DialOptions{
			HTTPHeader: http.Header{},
			HTTPClient: &http.Client{Transport: transport},
		}
		c.dialOptions.HTTPHeader.Add("Host", host)
		c.uri = fmt.Sprintf("%s://%s%s", protocol, host, getNormalizedPath(path))

		return c, nil
	}
}

func (c *Client) Conn(string) (net.Conn, error) {
	con, _, err := nyws.Dial(context.TODO(), c.uri, c.dialOptions)
	if err != nil {
		return nil, fmt.Errorf("websocket dial failed: %w", err)
	}
	return nyws.NetConn(context.TODO(), con, nyws.MessageBinary), nil
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
