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

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	pd "github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
	"github.com/Asutorufa/yuhaiin/pkg/utils"
	"github.com/Asutorufa/yuhaiin/pkg/utils/relay"
)

func init() {
	Register(pd.Type_doh, NewDoH)
}

func NewDoH(config Config) (dns.DNS, error) {
	req, err := getRequest(config.Host)
	if err != nil {
		return nil, err
	}

	if config.Servername == "" {
		config.Servername = req.Clone(context.TODO(), nil).URL.Hostname()
	}

	tlsConfig := &tls.Config{
		ServerName: config.Servername,
	}

	roundTripper := &http.Transport{
		TLSClientConfig:   tlsConfig,
		ForceAttemptHTTP2: true,
		DialContext: func(ctx context.Context, network, host string) (net.Conn, error) {
			switch network {
			case "tcp", "tcp4", "tcp6":
				addr, err := proxy.ParseAddress(proxy.PaseNetwork(network), host)
				if err != nil {
					return nil, fmt.Errorf("doh parse address failed: %w", err)
				}

				return config.Dialer.Conn(ctx, addr)
			default:
				return nil, fmt.Errorf("unsupported network: %s", network)
			}
		},
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	return NewClient(config, func(ctx context.Context, b []byte) ([]byte, error) {
		resp, err := roundTripper.RoundTrip(req.Clone(ctx, b))
		if err != nil {
			return nil, fmt.Errorf("doh post failed: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			relay.Copy(io.Discard, resp.Body) // By consuming the whole body the TLS connection may be reused on the next request.
			return nil, fmt.Errorf("doh post return code: %d", resp.StatusCode)
		}

		return io.ReadAll(resp.Body)

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
	scheme, rest, _ := utils.GetScheme(host)
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
	req.Body = io.NopCloser(bytes.NewBuffer(body))
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(body)), nil
	}

	return req
}
