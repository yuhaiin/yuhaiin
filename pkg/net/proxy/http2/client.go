package http2

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	proxy "github.com/Asutorufa/yuhaiin/pkg/net/interfaces"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	"golang.org/x/net/http2"
)

type Client struct {
	client *http.Client
	proxy.Proxy
	host string
}

func NewClient(config *protocol.Protocol_Http2) protocol.WrapProxy {
	return func(p proxy.Proxy) (proxy.Proxy, error) {

		transport := &http2.Transport{
			DisableCompression: true,
			AllowHTTP:          true,
			ReadIdleTimeout:    time.Second * 20,
			DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
				address, err := proxy.ParseAddress(statistic.Type_tcp, addr)
				if err != nil {
					return nil, err
				}
				conn, err := p.Conn(ctx, address)
				if err != nil {
					return nil, fmt.Errorf("http2 dial tls context failed: %w", err)
				}

				return conn, nil
			},
		}

		client := &http.Client{
			Transport: transport,
		}

		if config.Http2.Host == "" {
			config.Http2.Host = "www.example.com"
		}

		return &Client{client, p, config.Http2.Host}, nil
	}
}

func (c *Client) Conn(ctx context.Context, addr proxy.Address) (net.Conn, error) {
	r, w := net.Pipe()

	req, err := http.NewRequest(http.MethodPost, "https://"+c.host, r)
	if err != nil {
		return nil, err
	}

	req.Proto = "HTTP/2"
	req.ProtoMajor = 2
	req.ProtoMinor = 0

	// Disable any compression method from server.
	req.Header.Set("Accept-Encoding", "identity")

	respr := &readCloser{
		wait: make(chan struct{}),
	}

	h2conn := &http2Conn{
		w:          w,
		r:          respr,
		localAddr:  caddr{},
		remoteAddr: addr,
	}

	go func() {
		resp, err := c.client.Do(req)
		if err != nil {
			r.Close()
			w.Close()
			respr.Close()
			log.Println("http2 do request failed:", err)
			return
		}

		respr.SetReadCloser(resp.Body)
	}()

	return h2conn, nil
}

type caddr struct{}

func (caddr) Network() string { return "tcp" }
func (caddr) String() string  { return "http2" }

type readCloser struct {
	mu   sync.Mutex
	rc   io.ReadCloser
	wait chan struct{}
}

func (r *readCloser) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.rc != nil {
		return r.rc.Close()
	}

	select {
	case <-r.wait:
	default:
		close(r.wait)
	}

	return nil
}

func (r *readCloser) SetReadCloser(rc io.ReadCloser) {
	r.mu.Lock()
	defer r.mu.Unlock()

	select {
	case <-r.wait:
	default:
		r.rc = rc
		close(r.wait)
	}
}

func (r *readCloser) Read(b []byte) (int, error) {
	if r.rc == nil {
		<-r.wait
		if r.rc == nil {
			return 0, net.ErrClosed
		}
	}

	n, err := r.rc.Read(b)
	if err != nil {
		if strings.Contains(err.Error(), "http2: response body closed") {
			err = net.ErrClosed
		}

		return n, err
	}

	return n, nil
}
