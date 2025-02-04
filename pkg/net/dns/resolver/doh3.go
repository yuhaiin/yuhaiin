package resolver

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"github.com/Asutorufa/yuhaiin/pkg/utils/relay"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func init() {
	Register(dns.Type_doh3, NewDoH3)
}

func NewDoH3(config Config) (Dialer, error) {
	tr := &http3.RoundTripper{
		Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
			ad, err := netapi.ParseAddress("udp", addr)
			if err != nil {
				return nil, err
			}

			conn, err := config.Dialer.PacketConn(ctx, ad)
			if err != nil {
				return nil, err
			}

			c := &DOQBufferWrapConn{direct.NewBufferPacketConn(conn), fmt.Sprint(doqIgGenerate.Generate())}
			return quic.DialEarly(ctx, c, ad, tlsCfg, cfg)
		},
	}

	req, err := getRequest(config.Host)
	if err != nil {
		return nil, fmt.Errorf("get request failed: %w", err)
	}

	return DialerFunc(func(ctx context.Context, b *Request) (Response, error) {
		resp, err := tr.RoundTrip(req.Clone(ctx, b.QuestionBytes))
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

		return BytesResponse(buf), nil
	}), nil
}
