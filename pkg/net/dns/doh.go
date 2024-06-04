package dns

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	pd "github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	ynet "github.com/Asutorufa/yuhaiin/pkg/utils/net"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"github.com/Asutorufa/yuhaiin/pkg/utils/relay"
)

func init() {
	Register(pd.Type_doh, NewDoH)
}

func NewDoH(config Config) (netapi.Resolver, error) {
	req, err := getRequest(config.Host)
	if err != nil {
		return nil, err
	}

	host := req.r.Host
	_, port, err := net.SplitHostPort(req.r.Host)
	if err != nil || port == "" {
		host = net.JoinHostPort(host, "443")
	}

	addr, err := netapi.ParseAddress(statistic.Type_tcp, host)
	if err != nil {
		return nil, err
	}

	if config.Servername == "" {
		config.Servername = req.Clone(context.TODO(), nil).URL.Hostname()
	}

	tlsConfig := &tls.Config{
		ServerName: config.Servername,
	}

	type transportStore struct {
		transport *transport
		time      time.Time
	}

	roundTripper := atomic.Pointer[transportStore]{}

	var changing atomic.Bool

	refreshRoundTripper := func() {
		rt := roundTripper.Load()
		if rt != nil {
			if time.Since(rt.time) <= time.Second*5 {
				return
			}

			rt.transport.Close()
		}

		if changing.CompareAndSwap(false, true) {
			roundTripper.Store(&transportStore{
				transport: newTransport(&http.Transport{
					TLSClientConfig:   tlsConfig,
					ForceAttemptHTTP2: true,
					DialContext: func(ctx context.Context, network, host string) (net.Conn, error) {
						return config.Dialer.Conn(ctx, addr)
					},
					MaxIdleConns:          100,
					IdleConnTimeout:       90 * time.Second,
					TLSHandshakeTimeout:   10 * time.Second,
					ExpectContinueTimeout: 1 * time.Second,
				}),
				time: time.Now(),
			})
			changing.Store(false)
		}
	}

	refreshRoundTripper()

	return NewClient(config, func(ctx context.Context, b *request) ([]byte, error) {
		resp, err := roundTripper.Load().transport.RoundTrip(req.Clone(ctx, b.Question))
		if err != nil {
			refreshRoundTripper() // https://github.com/golang/go/issues/30702
			return nil, fmt.Errorf("doh post failed: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			_, _ = relay.Copy(io.Discard, resp.Body) // By consuming the whole body the TLS connection may be reused on the next request.
			return nil, fmt.Errorf("doh post return code: %d", resp.StatusCode)
		}

		if resp.ContentLength <= 0 || resp.ContentLength > pool.MaxLength {
			return nil, fmt.Errorf("response content length is empty: %d", resp.ContentLength)
		}

		buf := pool.GetBytes(resp.ContentLength)

		_, err = io.ReadFull(resp.Body, buf)
		if err != nil {
			pool.PutBytes(buf)
			return nil, fmt.Errorf("doh post failed: %w", err)
		}

		return buf, nil

		/*
			* Get
			urls := fmt.Sprintf(
				"%s?dns=%s",
				url,
				strings.TrimSuffix(base64.URLEncoding.EncodeToString(dReq), "="),
			)
			resp, err := httpClient.Get(urls)
		*/
	}), nil
}

// https://tools.ietf.org/html/rfc8484
func getUrlAndHost(host string) string {
	scheme, rest, _ := ynet.GetScheme(host)
	if scheme == "" {
		host = "https://" + host
	}

	rest = strings.TrimPrefix(rest, "//")

	if rest == "" {
		host += "no-host-specified"
	}

	if !strings.Contains(rest, "/") {
		host = host + "/dns-query"
	}

	return host
}

type post struct {
	r *http.Request
}

func getRequest(host string) (*post, error) {
	uri := getUrlAndHost(host)
	req, err := http.NewRequest(http.MethodPost, uri, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	return &post{req}, nil
}

func (p *post) Clone(ctx context.Context, body []byte) *http.Request {
	req := p.r.Clone(ctx)
	req.ContentLength = int64(len(body))
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(body)), nil
	}

	return req
}

type transport struct {
	*http.Transport

	mu          sync.Mutex
	conns       []net.Conn
	dialContext func(ctx context.Context, network, addr string) (net.Conn, error)
}

func newTransport(p *http.Transport) *transport {
	t := &transport{}

	t.dialContext = p.DialContext
	p.DialContext = t.DialContext

	t.Transport = p

	return t
}

func (t *transport) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	conn, err := t.dialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	t.mu.Lock()
	t.conns = append(t.conns, conn)
	t.mu.Unlock()

	return conn, nil
}

func (t *transport) Close() {
	for _, v := range t.conns {
		_ = v.Close()
	}
	t.Transport.CloseIdleConnections()
}
