package resolver

import (
	"cmp"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	contractresolver "github.com/Asutorufa/yuhaiin/pkg/contract/resolver"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/utils/system"
)

func (r *Resolver) DNSCache() contractresolver.DNSCacheList {
	items := make([]contractresolver.DNSCacheEntry, 0)
	appendResolver := func(name string, resolver netapi.Resolver) {
		provider, ok := resolver.(netapi.DNSCacheProvider)
		if !ok {
			return
		}
		for _, entry := range provider.DNSCacheEntries() {
			item := contractresolver.DNSCacheEntry{
				Resolver:  name,
				Domain:    strings.TrimSuffix(entry.Question.Name, "."),
				QueryType: dnsutil.TypeToString(entry.Question.Qtype),
				Records:   make([]contractresolver.DNSCacheRecord, 0),
				ExpiresIn: uint32(max(entry.ExpiresIn/time.Second, 0)),
			}
			if item.Domain == "" {
				item.Domain = "."
			}
			if entry.Message != nil {
				item.Rcode = dnsutil.RcodeToString(entry.Message.Rcode)
				item.Records = appendDNSCacheRecords(item.Records, "answer", entry.Message.Answer)
				item.Records = appendDNSCacheRecords(item.Records, "authority", entry.Message.Ns)
				item.Records = appendDNSCacheRecords(item.Records, "additional", entry.Message.Extra)
			}
			items = append(items, item)
		}
	}

	appendResolver("bootstrap", netapi.Bootstrap())
	if r != nil {
		r.store.Range(func(name string, entry *Entry) bool {
			if entry != nil && entry.Resolver != nil {
				appendResolver(name, entry.Resolver)
			}
			return true
		})
	}

	slices.SortStableFunc(items, func(a, b contractresolver.DNSCacheEntry) int {
		if a.Resolver != b.Resolver {
			return cmp.Compare(a.Resolver, b.Resolver)
		}
		if strings.EqualFold(a.Domain, b.Domain) {
			return cmp.Compare(a.QueryType, b.QueryType)
		}
		return cmp.Compare(strings.ToLower(a.Domain), strings.ToLower(b.Domain))
	})
	return contractresolver.DNSCacheList{Items: items}
}

func appendDNSCacheRecords(records []contractresolver.DNSCacheRecord, section string, values []dns.RR) []contractresolver.DNSCacheRecord {
	for _, rr := range values {
		if rr == nil {
			continue
		}
		records = append(records, contractresolver.DNSCacheRecord{
			Section: section,
			Type:    dnsutil.TypeToString(dns.RRToType(rr)),
			Value:   rr.String(),
		})
	}
	return records
}

func (r *Resolver) ClearDNSCache(name, domain string) (int, error) {
	if r == nil {
		return 0, errors.New("resolver manager is unavailable")
	}

	var resolver netapi.Resolver
	if name == "bootstrap" {
		resolver = netapi.Bootstrap()
	} else {
		entry, ok := r.store.Load(name)
		if !ok || entry == nil || entry.Resolver == nil {
			return 0, fmt.Errorf("%w: %s", contractresolver.ErrDNSCacheNotFound, name)
		}
		resolver = entry.Resolver
	}

	provider, ok := resolver.(netapi.DNSCacheProvider)
	if !ok {
		return 0, nil
	}
	return provider.ClearDNSCache(domain), nil
}

func validateDNSCacheDomain(domain string) error {
	if strings.TrimSpace(domain) == "" || !system.IsDomainName(domain) {
		return fmt.Errorf("invalid domain: %q", domain)
	}
	return nil
}
