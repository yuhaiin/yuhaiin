package resolver

import (
	"errors"
	"fmt"
	"strings"
)

type Resolver struct {
	ID            string `json:"id"`
	Type          string `json:"type"`
	Host          string `json:"host"`
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
