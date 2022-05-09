package latency

import (
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
)

func DNS(p proxy.Proxy, host, target string) (time.Duration, error) {
	d := dns.NewDoU(host, nil, p)

	start := time.Now()

	_, err := d.LookupIP(target)
	if err != nil {
		return 0, err
	}

	return time.Since(start), nil
}
