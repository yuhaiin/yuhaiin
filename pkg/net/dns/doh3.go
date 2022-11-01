package dns

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/dns"
	pdns "github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
	"github.com/lucas-clemente/quic-go/http3"
)

func init() {
	Register(pdns.Type_doh3, NewDoH3)
}

type doh3 struct{ *client }

func NewDoH3(config Config) dns.DNS {
	d := &doh3{}

	tr := &http3.RoundTripper{}

	httpClient := &http.Client{
		Timeout:   time.Second * 5,
		Transport: tr,
	}

	if !strings.HasPrefix(config.Host, "https://") {
		config.Host = "https://" + config.Host
	}
	uri, err := url.Parse(config.Host)
	if err == nil && uri.Path == "" {
		config.Host += "/dns-query"
	}

	d.client = NewClient(config, func(b []byte) ([]byte, error) {
		resp, err := httpClient.Post(config.Host, "application/dns-message", bytes.NewBuffer(b))
		if err != nil {
			return nil, fmt.Errorf("doh post failed: %v", err)
		}
		defer resp.Body.Close()
		return io.ReadAll(resp.Body)
	})

	return d
}

func (d *doh3) Resolver() *net.Resolver {
	return net.DefaultResolver
}

func (d *doh3) Close() error { return nil }
