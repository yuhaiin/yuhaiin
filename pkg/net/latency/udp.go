package latency

import (
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	pdns "github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
)

func DNS(p proxy.Proxy, host, target string) (time.Duration, error) {
	d := dns.New(dns.Config{
		Type:   pdns.Type_udp,
		Host:   host,
		Dialer: p,
		IPv6:   true,
	})

	start := time.Now()

	_, err := d.LookupIP(target)
	if err != nil {
		return 0, err
	}

	return time.Since(start), nil
}

func DNSOverQuic(p proxy.Proxy, host, target string) (time.Duration, error) {
	d := dns.New(
		dns.Config{
			Type:   pdns.Type_doq,
			Host:   host,
			Dialer: p,
			IPv6:   true,
		},
	)

	start := time.Now()

	_, err := d.LookupIP(target)
	if err != nil {
		return 0, err
	}

	return time.Since(start), nil
}
