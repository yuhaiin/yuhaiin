package migrate

import (
	"errors"

	contractresolver "github.com/Asutorufa/yuhaiin/pkg/contract/resolver"
	legacy "github.com/Asutorufa/yuhaiin/pkg/legacy/schema/config"
)

func ConvertLegacyResolver(id string, old *legacy.Dns) (contractresolver.Resolver, error) {
	if id == "bootstrap" && (old == nil || old.GetHost() == "") {
		return contractresolver.Resolver{ID: id, Type: "system", Host: "system default", System: true}, nil
	}
	if old == nil {
		return contractresolver.Resolver{}, errors.New("legacy resolver is nil")
	}
	out := contractresolver.Resolver{
		ID:            id,
		Type:          legacyResolverTypeToContract(old.GetType()),
		Host:          old.GetHost(),
		Subnet:        old.GetSubnet(),
		TLSServerName: old.GetTlsServername(),
		System:        id == "bootstrap",
	}
	return out, out.Validate()
}

func ConvertContractResolver(in contractresolver.Resolver) (*legacy.Dns, error) {
	if err := in.Validate(); err != nil {
		return nil, err
	}
	if in.Type == "system" {
		in.Type = "udp"
	}
	return legacy.Dns_builder{
		Host:          &in.Host,
		Type:          contractResolverTypeToLegacy(in.Type).Enum(),
		Subnet:        &in.Subnet,
		TlsServername: &in.TLSServerName,
	}.Build(), nil
}

func ConvertLegacyFakeDNS(in *legacy.FakednsConfig) contractresolver.FakeDNS {
	if in == nil {
		return contractresolver.FakeDNS{}
	}
	return contractresolver.FakeDNS{
		Enabled:       in.GetEnabled(),
		IPv4Range:     in.GetIpv4Range(),
		IPv6Range:     in.GetIpv6Range(),
		Whitelist:     in.GetWhitelist(),
		SkipCheckList: in.GetSkipCheckList(),
	}
}

func ConvertContractFakeDNS(in contractresolver.FakeDNS) *legacy.FakednsConfig {
	return &legacy.FakednsConfig{
		Enabled:       in.Enabled,
		Ipv4Range:     in.IPv4Range,
		Ipv6Range:     in.IPv6Range,
		Whitelist:     in.Whitelist,
		SkipCheckList: in.SkipCheckList,
	}
}

func legacyResolverTypeToContract(typ legacy.Type) string {
	switch typ {
	case legacy.Type_tcp:
		return "tcp"
	case legacy.Type_doh:
		return "doh"
	case legacy.Type_dot:
		return "dot"
	case legacy.Type_doq:
		return "doq"
	case legacy.Type_doh3:
		return "doh3"
	default:
		return "udp"
	}
}

func contractResolverTypeToLegacy(typ string) legacy.Type {
	switch typ {
	case "tcp":
		return legacy.Type_tcp
	case "doh":
		return legacy.Type_doh
	case "dot":
		return legacy.Type_dot
	case "doq":
		return legacy.Type_doq
	case "doh3":
		return legacy.Type_doh3
	default:
		return legacy.Type_udp
	}
}
