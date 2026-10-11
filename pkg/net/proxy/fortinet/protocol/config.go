package fortinet

// The tunnel configuration exchanged as XML at /remote/fortisslvpn_xml.
//
// The server builds this from the address it assigned; the client parses it to
// learn its address, DNS and routes. The element and attribute names are
// openconnect's — <sslvpn-tunnel> at the root, <ipv4><assigned-addr ipv4=…>,
// <dns ip=… domain=…>, and <split-tunnel-info><addr ip=… mask=…> — so the two
// interoperate with real FortiOS and with the openconnect client.

import (
	"encoding/xml"
	"fmt"
	"net"
	"strings"
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

// BuildConfigXML renders a Config as the fortisslvpn_xml document. A full tunnel
// (no Include routes) omits <split-tunnel-info> entirely, which is how the client
// is told to route everything — the presence of split-includes is what switches
// it to split tunnelling. The dtls attribute advertises the UDP data channel;
// dtls="0" leaves a client that would prefer it on the TLS tunnel.
func BuildConfigXML(cfg Config) []byte {
	dtls := "0"
	if cfg.DTLS {
		dtls = "1"
	}
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="utf-8"?>`)
	b.WriteString(`<sslvpn-tunnel ver="2" dtls="` + dtls + `">`)
	b.WriteString(`<ipv4>`)
	fmt.Fprintf(&b, `<assigned-addr ipv4=%q/>`, cfg.AssignedIP.String())
	for _, d := range cfg.DNS {
		if cfg.Domain != "" {
			fmt.Fprintf(&b, `<dns ip=%q domain=%q/>`, d.String(), cfg.Domain)
		} else {
			fmt.Fprintf(&b, `<dns ip=%q/>`, d.String())
		}
	}
	writeSplit(&b, cfg.Include, false)
	writeSplit(&b, cfg.Exclude, true)
	b.WriteString(`</ipv4>`)
	b.WriteString(`<idle-timeout val="3600"/><auth-timeout val="18000"/>`)
	b.WriteString(`</sslvpn-tunnel>`)
	return []byte(b.String())
}

func writeSplit(b *strings.Builder, routes []Route, negate bool) {
	if len(routes) == 0 {
		return
	}
	if negate {
		b.WriteString(`<split-tunnel-info negate="1">`)
	} else {
		b.WriteString(`<split-tunnel-info>`)
	}
	for _, r := range routes {
		fmt.Fprintf(b, `<addr ip=%q mask=%q/>`, r.IP.String(), net.IP(r.Mask).String())
	}
	b.WriteString(`</split-tunnel-info>`)
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
