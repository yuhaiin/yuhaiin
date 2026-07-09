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
