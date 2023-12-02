package http2

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"golang.org/x/net/http2"
)

type Client struct {
	client *http2.Transport
	netapi.Proxy
}

func NewClient(config *protocol.Protocol_Http2) protocol.WrapProxy {
	return func(p netapi.Proxy) (netapi.Proxy, error) {
		transport := &http2.Transport{
			DisableCompression: true,
			AllowHTTP:          true,
			ReadIdleTimeout:    time.Second * 5,
			DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
				return p.Conn(ctx, netapi.EmptyAddr)
			},
		}

		return &Client{transport, p}, nil
	}
}

func (c *Client) Conn(ctx context.Context, addr netapi.Address) (net.Conn, error) {
	r, w := net.Pipe()

	req := &http.Request{
		Method:     http.MethodConnect,
		Body:       r,
		URL:        &url.URL{Scheme: "https", Host: "localhost"},
		Proto:      "HTTP/2.0",
		ProtoMajor: 2,
		ProtoMinor: 0,
	}

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
		resp, err := c.client.RoundTrip(req)
		if err != nil {
			r.Close()
			h2conn.Close()
			log.Error("http2 do request failed:", "err", err)
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
