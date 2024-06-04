package dns

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"github.com/Asutorufa/yuhaiin/pkg/utils/relay"
	"github.com/quic-go/quic-go/http3"
)

func init() {
	Register(dns.Type_doh3, NewDoH3)
}

func NewDoH3(config Config) (netapi.Resolver, error) {
	tr := &http3.RoundTripper{}

	req, err := getRequest(config.Host)
	if err != nil {
		return nil, fmt.Errorf("get request failed: %w", err)
	}

	return NewClient(config, func(ctx context.Context, b *request) ([]byte, error) {
		resp, err := tr.RoundTrip(req.Clone(ctx, b.Question))
		if err != nil {
			return nil, fmt.Errorf("doh post failed: %w", err)
		}

		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			_, _ = relay.Copy(io.Discard, resp.Body) // from v2fly
			return nil, fmt.Errorf("doh post return code: %d", resp.StatusCode)
		}

		if resp.ContentLength <= 0 || resp.ContentLength > pool.MaxLength {
			return nil, fmt.Errorf("response content length is empty: %d", resp.ContentLength)
		}

		buf := pool.GetBytes(resp.ContentLength)

		_, err = io.ReadFull(resp.Body, buf)
		if err != nil {
			pool.PutBytes(buf)
			return nil, fmt.Errorf("doh3 post failed: %w", err)
		}

		return buf, nil
	}), nil
}
