package resolver

import (
	"cmp"
	"context"
	"errors"
	"maps"
	"slices"
	"strings"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	contractresolver "github.com/Asutorufa/yuhaiin/pkg/contract/resolver"
	dnsresolver "github.com/Asutorufa/yuhaiin/pkg/net/dns/resolver"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/security/secret"
)

// QueryTypes uses the wire library's registry, excluding message metadata and
// zone transfers, which the one-response diagnostic query does not implement.
func QueryTypes() contractresolver.QueryTypeList {
	types := slices.Sorted(maps.Values(dns.TypeToString))
	types = slices.DeleteFunc(types, func(name string) bool { return name == "OPT" || name == "TSIG" || name == "AXFR" || name == "IXFR" })
	return contractresolver.QueryTypeList{Types: types}
}

func (c ContractController) Test(ctx context.Context, request contractresolver.TestRequest) (contractresolver.TestResponse, error) {
	if c.resolver == nil || c.resolver.r == nil {
		return contractresolver.TestResponse{}, errors.New("resolver controller is unavailable")
	}
	if err := request.Validate(); err != nil {
		return contractresolver.TestResponse{}, err
	}
	config, err := c.resolver.mergeSecretDraft(ctx, request.Resolver)
	if err != nil {
		return contractresolver.TestResponse{}, err
	}
	config.ID = cmp.Or(config.ID, "resolver-test")
	queryType := strings.ToUpper(cmp.Or(strings.TrimSpace(request.QueryType), "A"))
	domain := dnsutil.Fqdn(strings.TrimSpace(request.Domain))
	result := contractresolver.TestResponse{Domain: domain, QueryType: queryType, Records: []contractresolver.DNSCacheRecord{}}
	start := time.Now()
	dialer := &dnsDialer{Proxy: c.resolver.r.dialer, resolver: netapi.Bootstrap, name: config.ID}
	if config.ID == "bootstrap" {
		dialer.bootstrap = true
		dialer.resolver = func() netapi.Resolver { return dnsresolver.Internet }
	}
	// A fresh client exercises the displayed draft, bypassing existing DNS caches
	// and leaving the stored/active resolver and bootstrap configuration untouched.
	probe, err := newContractResolver(config, dialer)
	if err != nil {
		result.Error = secret.RemoteError(err).Error()
		result.ElapsedMS = float64(time.Since(start)) / float64(time.Millisecond)
		return result, nil
	}
	defer func() { _ = probe.Close() }()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	message, err := probe.Raw(netapi.WithContext(ctx), netapi.DNSQuestion{Name: domain, Qtype: dns.StringToType[queryType], Qclass: dns.ClassINET})
	result.ElapsedMS = float64(time.Since(start)) / float64(time.Millisecond)
	if err != nil {
		result.Error = secret.RemoteError(err).Error()
		return result, nil
	}
	if message == nil {
		result.Error = "resolver returned no DNS response"
		return result, nil
	}
	result.Rcode = dnsutil.RcodeToString(message.Rcode)
	result.Truncated = message.Truncated
	result.Records = appendDNSCacheRecords(result.Records, "answer", message.Answer)
	result.Records = appendDNSCacheRecords(result.Records, "authority", message.Ns)
	result.Records = appendDNSCacheRecords(result.Records, "additional", message.Extra)
	return result, nil
}
