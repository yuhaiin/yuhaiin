package resolver

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"github.com/Asutorufa/yuhaiin/pkg/utils/relay"
	"golang.org/x/net/http2"
)

func init() {
	Register(config.Type_doh, NewDoH)
}

func NewDoH(config Config) (Transport, error) {
	u, err := parseDohUrl(config.Host)
	if err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{
		ServerName: config.serverName(u),
	}

	tr := &http.Transport{
		TLSClientConfig:   tlsConfig,
		ForceAttemptHTTP2: true,
		DialContext: func(ctx context.Context, network, host string) (net.Conn, error) {
			addr, err := netapi.ParseAddress(network, host)
			if err != nil {
				return nil, err
			}

			// the deadline of [http.Request] will be ignored when http2?
			// so we check and set timeout here
			// see: https://github.com/golang/go/blob/f15cd63ec4860c4f2c23cc992843546e0265c332/src/net/http/transport.go#L1510
			if _, ok := ctx.Deadline(); !ok {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, configuration.ResolverTimeout)
				defer cancel()
			}

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

	tr2.PingTimeout = 5 * time.Second
	tr2.ReadIdleTimeout = time.Second * 30 // https://github.com/golang/go/issues/30702
	tr2.IdleConnTimeout = time.Second * 90

	uri := u.String()

	return TransportFunc(func(ctx context.Context, b *Request) (Response, error) {
		req, err := newDohRequest(ctx, http.MethodPost, uri, b.Bytes())
		if err != nil {
			return nil, err
		}

		resp, err := tr.RoundTrip(req)
		if err != nil {
			return nil, fmt.Errorf("doh post failed: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			_, _ = relay.Copy(io.Discard, resp.Body) // By consuming the whole body the TLS connection may be reused on the next request.
			return nil, fmt.Errorf("doh post return code: %d", resp.StatusCode)
		}

		if resp.ContentLength <= 0 || resp.ContentLength > pool.MaxSegmentSize {
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
func parseDohUrl(host string) (*url.URL, error) {
	if !strings.HasPrefix(host, "http://") && !strings.HasPrefix(host, "https://") {
		host = "https://" + host
	}

	pi := strings.Index(host, "://") + 3

	if len(host[pi:]) == 0 {
		return nil, fmt.Errorf("invalid host: [%s](len: %d)", host[pi:], len(host[pi:]))
	}

	i := strings.Index(host[pi:], "/")
	if i == -1 {
		host += "/dns-query"
	} else {
		domain := host[pi : pi+i]
		if len(domain) == 0 {
			return nil, fmt.Errorf("invalid host: [%s](len: %d)", domain, len(domain))
		}
	}

	return url.Parse(host)
}

func newDohRequest(ctx context.Context, method string, uri string, body []byte) (*http.Request, error) {
	var req *http.Request
	var err error
	switch method {
	case http.MethodGet:
		b64str := base64.URLEncoding.EncodeToString(body)
		if i := strings.Index("uri", "?"); i != -1 {
			uri += "&dns=" + b64str
		} else {
			uri += "?dns=" + b64str
		}
		req, err = http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	case http.MethodPost:
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, uri, bytes.NewReader(body))
	default:
		return nil, fmt.Errorf("invalid method: %s", method)
	}
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	return req, nil
}
