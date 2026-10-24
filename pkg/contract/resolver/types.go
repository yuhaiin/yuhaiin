package resolver

import (
	"cmp"
	"errors"
	"fmt"
	"strings"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

type Resolver struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Type          string `json:"type"`
	Host          string `json:"host" secret:"url"`
	Subnet        string `json:"subnet,omitzero"`
	TLSServerName string `json:"tlsServerName,omitzero"`
	System        bool   `json:"system,omitzero"`
}

type Hosts struct {
	Hosts map[string]string `json:"hosts"`
}

type FakeDNS struct {
	Enabled       bool     `json:"enabled"`
	IPv4Range     string   `json:"ipv4Range"`
	IPv6Range     string   `json:"ipv6Range"`
	Whitelist     []string `json:"whitelist"`
	SkipCheckList []string `json:"skipCheckList"`
}

type Server struct {
	Server string `json:"server"`
}

type DNSCacheRecord struct {
	Section string `json:"section"`
	Type    string `json:"type"`
	Value   string `json:"value"`
}

type DNSCacheEntry struct {
	Resolver  string           `json:"resolver"`
	Domain    string           `json:"domain"`
	QueryType string           `json:"queryType"`
	Rcode     string           `json:"rcode"`
	Records   []DNSCacheRecord `json:"records"`
	ExpiresIn uint32           `json:"expiresIn"`
}

type DNSCacheList struct {
	Items []DNSCacheEntry `json:"items"`
}

type DNSCacheClearResponse struct {
	Removed int `json:"removed"`
}

var ErrDNSCacheNotFound = errors.New("resolver cache is not active")

func (x Resolver) Validate() error {
	if strings.TrimSpace(x.ID) == "" {
		return errors.New("resolver id is empty")
	}
	switch x.Type {
	case "udp", "tcp", "doh", "dot", "doq", "doh3", "system":
	default:
		return fmt.Errorf("unknown resolver type %q", x.Type)
	}
	if x.Type != "system" && strings.TrimSpace(x.Host) == "" {
		return errors.New("resolver host is empty")
	}
	return nil
}

type QueryTypeList struct {
	Types []string `json:"types"`
}

type TestRequest struct {
	Resolver  Resolver `json:"resolver"`
	Domain    string   `json:"domain"`
	QueryType string   `json:"queryType"`
}

type TestResponse struct {
	Domain    string           `json:"domain"`
	QueryType string           `json:"queryType"`
	ElapsedMS float64          `json:"elapsedMs"`
	Rcode     string           `json:"rcode"`
	Truncated bool             `json:"truncated"`
	Records   []DNSCacheRecord `json:"records"`
	Error     string           `json:"error,omitzero"`
}

func (r TestRequest) Validate() error {
	if strings.TrimSpace(r.Domain) == "" || strings.ContainsAny(r.Domain, ":/\\ \t\r\n?#@") || !dnsutil.IsName(strings.TrimSpace(r.Domain)) {
		return errors.New("invalid DNS query domain")
	}
	queryType := strings.ToUpper(strings.TrimSpace(r.QueryType))
	if queryType == "" {
		queryType = "A"
	}
	if _, ok := dns.StringToType[queryType]; !ok || queryType == "OPT" || queryType == "TSIG" || queryType == "AXFR" || queryType == "IXFR" {
		return fmt.Errorf("unsupported DNS query type %q", r.QueryType)
	}
	config := r.Resolver
	config.ID = cmp.Or(config.ID, "resolver-test")
	return config.Validate()
}
