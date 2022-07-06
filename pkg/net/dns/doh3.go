package dns

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/lucas-clemente/quic-go/http3"
)

func init() {
	Register(config.Dns_doh3, func(c dns.Config, p proxy.Proxy) dns.DNS { return NewDoH3(c) })
}

type doh3 struct{ *client }

func NewDoH3(config dns.Config) dns.DNS {
	d := &doh3{}

	httpClient := &http.Client{
		Timeout:   time.Second * 5,
		Transport: &http3.RoundTripper{},
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
		return ioutil.ReadAll(resp.Body)
	})

	return d
}

func (d *doh3) Resolver() *net.Resolver {
	return net.DefaultResolver
}

func (d *doh3) Close() error { return nil }
