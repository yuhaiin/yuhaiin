package dns

import (
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/dns"
	pdns "github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
	"github.com/Asutorufa/yuhaiin/pkg/utils/relay"
	"github.com/lucas-clemente/quic-go/http3"
)

func init() {
	Register(pdns.Type_doh3, NewDoH3)
}

func NewDoH3(config Config) (dns.DNS, error) {
	tr := &http3.RoundTripper{}

	httpClient := &http.Client{
		Timeout:   time.Second * 5,
		Transport: tr,
	}

	req, err := getRequest(config.Host)
	if err != nil {
		return nil, fmt.Errorf("get request failed: %w", err)
	}

	return NewClient(config, func(b []byte) ([]byte, error) {
		resp, err := httpClient.Do(req.Clone(b))
		if err != nil {
			return nil, fmt.Errorf("doh post failed: %w", err)
		}

		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			relay.Copy(io.Discard, resp.Body) // from v2fly
			return nil, fmt.Errorf("doh post return code: %d", resp.StatusCode)
		}
		return io.ReadAll(resp.Body)
	}), nil
}
