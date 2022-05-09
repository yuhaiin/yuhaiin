package dns

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/dns"
	"github.com/lucas-clemente/quic-go/http3"
)

type doh3 struct {
	url        string
	httpClient *http.Client

	*client
}

func NewDoH3(host string, subnet *net.IPNet) dns.DNS {
	d := &doh3{
		httpClient: &http.Client{
			Transport: &http3.RoundTripper{},
		},
	}

	d.setServer(host)

	d.client = NewClient(subnet, func(b []byte) ([]byte, error) {
		resp, err := d.httpClient.Post(d.url, "application/dns-message", bytes.NewBuffer(b))
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

func (d *doh3) setServer(host string) {
	if !strings.HasPrefix(host, "https://") {
		d.url = "https://" + host
	} else {
		d.url = host
	}

	uri, err := url.Parse(d.url)
	if err == nil && uri.Path == "" {
		d.url += "/dns-query"
	}
}

func (d *doh3) Close() error { return nil }
