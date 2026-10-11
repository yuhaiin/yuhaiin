package fortinet

// The tunnel configuration returned as XML at /remote/fortisslvpn_xml.

import (
	"encoding/xml"
	"fmt"
	"net"
)

// Route is one split-tunnel entry: a network and its mask.
type Route struct {
	IP   net.IP
	Mask net.IPMask
}

// Config is the parsed tunnel configuration.
type Config struct {
	// AssignedIP is the client's inner address.
	AssignedIP net.IP
	// DNS are the inner DNS servers; Domain is the search domain, if any.
	DNS    []net.IP
	Domain string
	// Include are split-include routes; empty means full tunnel (default route).
	Include []Route
	// Exclude are split-exclude routes (the negate="1" set).
	Exclude []Route
	// DTLS reports whether the gateway offers the UDP data channel, from the
	// dtls attribute on <sslvpn-tunnel>. A client that can speak it prefers it.
	DTLS bool
}

// xmlTunnel mirrors the parts of <sslvpn-tunnel> this code reads.
type xmlTunnel struct {
	XMLName xml.Name `xml:"sslvpn-tunnel"`
	DTLS    string   `xml:"dtls,attr"`
	IPv4    xmlIPv4  `xml:"ipv4"`
}

type xmlIPv4 struct {
	Assigned struct {
		IPv4 string `xml:"ipv4,attr"`
	} `xml:"assigned-addr"`
	DNS []struct {
		IP     string `xml:"ip,attr"`
		Domain string `xml:"domain,attr"`
	} `xml:"dns"`
	Splits []xmlSplit `xml:"split-tunnel-info"`
}

type xmlSplit struct {
	Negate string `xml:"negate,attr"`
	Addrs  []struct {
		IP   string `xml:"ip,attr"`
		Mask string `xml:"mask,attr"`
	} `xml:"addr"`
}

// ParseConfigXML decodes a fortisslvpn_xml document. Unknown elements and
// attributes are ignored, since FortiOS versions add fields freely and a client
// that rejected an unfamiliar tag would break on a routine server upgrade.
func ParseConfigXML(data []byte) (Config, error) {
	var t xmlTunnel
	if err := xml.Unmarshal(data, &t); err != nil {
		return Config{}, fmt.Errorf("fortinet: parsing config XML: %w", err)
	}

	var cfg Config
	cfg.DTLS = t.DTLS == "1"
	if s := t.IPv4.Assigned.IPv4; s != "" {
		cfg.AssignedIP = net.ParseIP(s)
		if cfg.AssignedIP == nil {
			return Config{}, fmt.Errorf("fortinet: assigned-addr %q is not an IP", s)
		}
	}
	for _, d := range t.IPv4.DNS {
		if ip := net.ParseIP(d.IP); ip != nil {
			cfg.DNS = append(cfg.DNS, ip)
		}
		if d.Domain != "" && cfg.Domain == "" {
			cfg.Domain = d.Domain
		}
	}
	for _, sp := range t.IPv4.Splits {
		for _, a := range sp.Addrs {
			ip := net.ParseIP(a.IP)
			mask := net.IPMask(net.ParseIP(a.Mask).To4())
			if ip == nil || mask == nil {
				continue
			}
			r := Route{IP: ip, Mask: mask}
			if sp.Negate == "1" {
				cfg.Exclude = append(cfg.Exclude, r)
			} else {
				cfg.Include = append(cfg.Include, r)
			}
		}
	}
	return cfg, nil
}
