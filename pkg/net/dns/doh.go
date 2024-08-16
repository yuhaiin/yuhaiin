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
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	pd "github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"github.com/Asutorufa/yuhaiin/pkg/utils/relay"
	"github.com/Asutorufa/yuhaiin/pkg/utils/system"
	"golang.org/x/net/http2"
)

func init() {
	Register(pd.Type_doh, NewDoH)
}

func NewDoH(config Config) (Dialer, error) {
	req, err := getRequest(config.Host)
	if err != nil {
		return nil, err
	}

	host := req.r.Host
	_, port, err := net.SplitHostPort(req.r.Host)
	if err != nil || port == "" {
		host = net.JoinHostPort(host, "443")
	}

	addr, err := netapi.ParseAddress("tcp", host)
	if err != nil {
		return nil, err
	}

	if config.Servername == "" {
		config.Servername = req.Clone(context.TODO(), nil).URL.Hostname()
	}

	tlsConfig := &tls.Config{
		ServerName: config.Servername,
	}

	tr := &http.Transport{
		TLSClientConfig:   tlsConfig,
		ForceAttemptHTTP2: true,
		DialContext: func(ctx context.Context, network, host string) (net.Conn, error) {
			return config.Dialer.Conn(ctx, addr)
		},
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	tr2, err := http2.ConfigureTransports(tr)
	if err != nil {
		return nil, err
	}

	tr2.ReadIdleTimeout = time.Second * 30 // https://github.com/golang/go/issues/30702
	tr2.IdleConnTimeout = time.Second * 90

	return DialerFunc(func(ctx context.Context, b *Request) (Response, error) {
		resp, err := tr.RoundTrip(req.Clone(ctx, b.QuestionBytes))
		if err != nil {
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
			return nil, fmt.Errorf("read http body failed: %w", err)
		}

		return BytesResponse(buf), nil

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
	scheme, rest, _ := system.GetScheme(host)
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
