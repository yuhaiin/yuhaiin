package latency

import (
	"context"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	pdns "github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
)

var timeout = 5 * time.Second

func DNS(p netapi.Proxy, host, target string) (time.Duration, error) {
	d, err := dns.New(dns.Config{
		Type:   pdns.Type_udp,
		Host:   host,
		Dialer: p,
	})
	if err != nil {
		return 0, err
	}
	defer d.Close()

	start := time.Now()

	ctx, cancel := context.WithTimeout(context.TODO(), timeout)
	defer cancel()

	_, err = d.LookupIP(ctx, target)
	if err != nil {
		return 0, err
	}

	return time.Since(start), nil
}

func DNSOverQuic(p netapi.Proxy, host, target string) (time.Duration, error) {
	d, err := dns.New(
		dns.Config{
			Type:   pdns.Type_doq,
			Host:   host,
			Dialer: p,
		},
	)
	if err != nil {
		return 0, err
	}
	defer d.Close()

	start := time.Now()

	ctx, cancel := context.WithTimeout(context.TODO(), timeout)
	defer cancel()

	_, err = d.LookupIP(ctx, target)
	if err != nil {
		return 0, err
	}

	return time.Since(start), nil
}
