package gp

// The tunnel configuration exchanged as XML at getconfig.esp.
//
// This is where GlobalProtect differs from every other protocol in this tree:
// the document does not merely describe the tunnel, it *contains the keys*. Both
// SPIs and all four ESP keys arrive here, in hex, over the authenticated HTTPS
// channel. There is no key exchange and no forward secrecy — whoever can read
// this document can read the tunnel it describes, for the tunnel's whole life.
// That is Palo Alto's design, not a shortcut taken here; internal/gp/README.md
// says so plainly, as does doc/security.md.

import (
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Route is one access-route entry.
type Route struct {
	IP   net.IP
	Mask net.IPMask
}

// String renders the route in the CIDR form the document carries.
func (r Route) String() string {
	ones, _ := r.Mask.Size()
	return r.IP.String() + "/" + strconv.Itoa(ones)
}

// Config is the parsed tunnel configuration.
type Config struct {
	// AssignedIP and Netmask are the client's inner address.
	AssignedIP net.IP
	Netmask    net.IPMask
	// GatewayAddr is the address the gateway answers ESP on, and the destination
	// of the activation pings. It is the gateway's own address, not an inner one.
	GatewayAddr net.IP
	// DNS are the inner DNS servers; Domain is the search domain, if any.
	DNS    []net.IP
	Domain string
	// MTU is the inner MTU the gateway suggests; 0 means it suggested none.
	MTU int
	// Include are access routes; empty means a full tunnel. Exclude are the
	// destinations to keep off the tunnel.
	Include []Route
	Exclude []Route
	// SSLTunnelURL is the path of the packet tunnel, normally PathTunnel.
	SSLTunnelURL string
	// Lifetime and Timeout are the session's limits in seconds, as advertised.
	Lifetime int
	Timeout  int
	// ESP carries the keying material when the gateway offers the ESP data path.
	// Nil means SSL-tunnel-only, which is a legitimate gateway configuration.
	ESP *ESPConfig
}

// ESPConfig is the keying material for the ESP data path, exactly as the
// document carries it. Directions are named from the client's point of view:
// c2s is what the client sends, s2c is what it receives.
type ESPConfig struct {
	// UDPPort is where ESP is exchanged; DefaultESPPort when unstated.
	UDPPort int
	// EncAlgo and HMACAlgo are the wire names, e.g. "aes-128-cbc" and "sha1".
	EncAlgo  string
	HMACAlgo string

	C2SSPI uint32
	S2CSPI uint32

	// EKey is the encryption key and AKey the authentication key, per direction.
	EKeyC2S []byte
	AKeyC2S []byte
	EKeyS2C []byte
	AKeyS2C []byte
}

// DefaultESPPort is where a gateway answers ESP unless the configuration says
// otherwise. It is not the IANA IPsec port: GlobalProtect uses its own.
const DefaultESPPort = 4501

// xmlConfig mirrors the parts of the getconfig response this code reads. Unknown
// elements are ignored, since PAN-OS versions add fields freely and a client that
// rejected an unfamiliar tag would break on a routine gateway upgrade.
type xmlConfig struct {
	XMLName      xml.Name   `xml:"response"`
	IPAddress    string     `xml:"ip-address"`
	Netmask      string     `xml:"netmask"`
	GWAddress    string     `xml:"gw-address"`
	MTU          string     `xml:"mtu"`
	Lifetime     string     `xml:"lifetime"`
	Timeout      string     `xml:"timeout"`
	SSLTunnelURL string     `xml:"ssl-tunnel-url"`
	Domain       string     `xml:"default-domain"`
	DNS          xmlMembers `xml:"dns"`
	Include      xmlMembers `xml:"access-routes"`
	Exclude      xmlMembers `xml:"exclude-access-routes"`
	IPSec        *xmlIPSec  `xml:"ipsec"`
}

type xmlMembers struct {
	Members []string `xml:"member"`
}

type xmlIPSec struct {
	UDPPort  string `xml:"udp-port"`
	Mode     string `xml:"ipsec-mode"`
	EncAlgo  string `xml:"enc-algo"`
	HMACAlgo string `xml:"hmac-algo"`
	C2SSPI   string `xml:"c2s-spi"`
	S2CSPI   string `xml:"s2c-spi"`
	AKeyS2C  xmlKey `xml:"akey-s2c"`
	EKeyS2C  xmlKey `xml:"ekey-s2c"`
	AKeyC2S  xmlKey `xml:"akey-c2s"`
	EKeyC2S  xmlKey `xml:"ekey-c2s"`
}

type xmlKey struct {
	Bits string `xml:"bits"`
	Val  string `xml:"val"`
}

// BuildConfigXML renders a Config as the getconfig response.
func BuildConfigXML(cfg Config) []byte {
	var b strings.Builder
	b.WriteString(xml.Header)
	b.WriteString("<response status=\"success\">")
	writeElem(&b, "ip-address", ipString(cfg.AssignedIP))
	if cfg.Netmask != nil {
		writeElem(&b, "netmask", net.IP(cfg.Netmask).String())
	}
	if cfg.GatewayAddr != nil {
		writeElem(&b, "gw-address", cfg.GatewayAddr.String())
	}
	if cfg.MTU > 0 {
		writeElem(&b, "mtu", strconv.Itoa(cfg.MTU))
	}
	if cfg.Lifetime > 0 {
		writeElem(&b, "lifetime", strconv.Itoa(cfg.Lifetime))
	}
	if cfg.Timeout > 0 {
		writeElem(&b, "timeout", strconv.Itoa(cfg.Timeout))
	}
	if cfg.Domain != "" {
		writeElem(&b, "default-domain", cfg.Domain)
	}
	if len(cfg.DNS) > 0 {
		b.WriteString("<dns>")
		for _, d := range cfg.DNS {
			writeElem(&b, "member", d.String())
		}
		b.WriteString("</dns>")
	}
	writeRoutes(&b, "access-routes", cfg.Include)
	writeRoutes(&b, "exclude-access-routes", cfg.Exclude)
	if cfg.ESP != nil {
		writeIPSec(&b, cfg.ESP)
	}
	url := cfg.SSLTunnelURL
	if url == "" {
		url = PathTunnel
	}
	writeElem(&b, "ssl-tunnel-url", url)
	b.WriteString("</response>")
	return []byte(b.String())
}

func writeElem(b *strings.Builder, name, val string) {
	b.WriteString("<" + name + ">")
	_ = xml.EscapeText(b, []byte(val))
	b.WriteString("</" + name + ">")
}

func writeRoutes(b *strings.Builder, name string, routes []Route) {
	if len(routes) == 0 {
		return
	}
	b.WriteString("<" + name + ">")
	for _, r := range routes {
		writeElem(b, "member", r.String())
	}
	b.WriteString("</" + name + ">")
}

func writeIPSec(b *strings.Builder, e *ESPConfig) {
	port := e.UDPPort
	if port == 0 {
		port = DefaultESPPort
	}
	b.WriteString("<ipsec>")
	writeElem(b, "udp-port", strconv.Itoa(port))
	writeElem(b, "ipsec-mode", "esp-tunnel")
	writeElem(b, "enc-algo", e.EncAlgo)
	writeElem(b, "hmac-algo", e.HMACAlgo)
	writeElem(b, "c2s-spi", spiString(e.C2SSPI))
	writeElem(b, "s2c-spi", spiString(e.S2CSPI))
	writeKey(b, "akey-s2c", e.AKeyS2C)
	writeKey(b, "ekey-s2c", e.EKeyS2C)
	writeKey(b, "akey-c2s", e.AKeyC2S)
	writeKey(b, "ekey-c2s", e.EKeyC2S)
	b.WriteString("</ipsec>")
}

func writeKey(b *strings.Builder, name string, key []byte) {
	b.WriteString("<" + name + ">")
	writeElem(b, "bits", strconv.Itoa(len(key)*8))
	writeElem(b, "val", hex.EncodeToString(key))
	b.WriteString("</" + name + ">")
}

// spiString renders an SPI the way the document carries it: 0x-prefixed hex.
func spiString(spi uint32) string {
	return "0x" + hex.EncodeToString([]byte{byte(spi >> 24), byte(spi >> 16), byte(spi >> 8), byte(spi)})
}

func ipString(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}

// ParseConfigXML decodes a getconfig response.
func ParseConfigXML(data []byte) (Config, error) {
	var doc xmlConfig
	if err := xml.Unmarshal(data, &doc); err != nil {
		return Config{}, fmt.Errorf("gp: parsing config XML: %w", err)
	}

	var cfg Config
	if s := strings.TrimSpace(doc.IPAddress); s != "" {
		if cfg.AssignedIP = net.ParseIP(s); cfg.AssignedIP == nil {
			return Config{}, fmt.Errorf("gp: ip-address %q is not an IP", s)
		}
	}
	if s := strings.TrimSpace(doc.Netmask); s != "" {
		m := net.ParseIP(s)
		if m == nil || m.To4() == nil {
			return Config{}, fmt.Errorf("gp: netmask %q is not an IPv4 mask", s)
		}
		cfg.Netmask = net.IPMask(m.To4())
	}
	if s := strings.TrimSpace(doc.GWAddress); s != "" {
		cfg.GatewayAddr = net.ParseIP(s)
	}
	cfg.MTU = atoiOr(doc.MTU, 0)
	cfg.Lifetime = atoiOr(doc.Lifetime, 0)
	cfg.Timeout = atoiOr(doc.Timeout, 0)
	cfg.Domain = strings.TrimSpace(doc.Domain)
	cfg.SSLTunnelURL = strings.TrimSpace(doc.SSLTunnelURL)

	for _, m := range doc.DNS.Members {
		if ip := net.ParseIP(strings.TrimSpace(m)); ip != nil {
			cfg.DNS = append(cfg.DNS, ip)
		}
	}
	cfg.Include = parseRoutes(doc.Include.Members)
	cfg.Exclude = parseRoutes(doc.Exclude.Members)

	if doc.IPSec != nil {
		esp, err := parseIPSec(doc.IPSec)
		if err != nil {
			return Config{}, err
		}
		cfg.ESP = esp
	}
	return cfg, nil
}

// parseRoutes decodes CIDR members, skipping ones that do not parse. A gateway
// that sends a malformed route should not cost the client its whole tunnel.
func parseRoutes(members []string) []Route {
	var out []Route
	for _, m := range members {
		ip, ipnet, err := net.ParseCIDR(strings.TrimSpace(m))
		if err != nil {
			continue
		}
		out = append(out, Route{IP: ip.Mask(ipnet.Mask), Mask: ipnet.Mask})
	}
	return out
}

func parseIPSec(x *xmlIPSec) (*ESPConfig, error) {
	// An <ipsec> block with no keys is how a gateway says "SSL tunnel only"
	// without omitting the element; treat it as no ESP rather than an error.
	if x.EncAlgo == "" && x.EKeyC2S.Val == "" {
		return nil, nil
	}
	e := &ESPConfig{
		UDPPort:  atoiOr(x.UDPPort, DefaultESPPort),
		EncAlgo:  strings.ToLower(strings.TrimSpace(x.EncAlgo)),
		HMACAlgo: strings.ToLower(strings.TrimSpace(x.HMACAlgo)),
	}
	var err error
	if e.C2SSPI, err = parseSPI(x.C2SSPI); err != nil {
		return nil, err
	}
	if e.S2CSPI, err = parseSPI(x.S2CSPI); err != nil {
		return nil, err
	}
	keys := []struct {
		name string
		src  xmlKey
		dst  *[]byte
	}{
		{"akey-s2c", x.AKeyS2C, &e.AKeyS2C},
		{"ekey-s2c", x.EKeyS2C, &e.EKeyS2C},
		{"akey-c2s", x.AKeyC2S, &e.AKeyC2S},
		{"ekey-c2s", x.EKeyC2S, &e.EKeyC2S},
	}
	for _, k := range keys {
		b, err := hex.DecodeString(strings.TrimSpace(k.src.Val))
		if err != nil {
			return nil, fmt.Errorf("gp: %s is not hex: %w", k.name, err)
		}
		// The <bits> element states the key's length. Where it is present and
		// disagrees with the hex, the document is internally inconsistent and is
		// rejected rather than guessed at — these are keys.
		if bits := atoiOr(k.src.Bits, 0); bits != 0 && bits != len(b)*8 {
			return nil, fmt.Errorf("gp: %s says %d bits but carries %d", k.name, bits, len(b)*8)
		}
		*k.dst = b
	}
	return e, nil
}

// parseSPI decodes an SPI, which the document carries as 0x-prefixed hex.
func parseSPI(s string) (uint32, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	v, err := strconv.ParseUint(strings.TrimPrefix(strings.ToLower(s), "0x"), 16, 32)
	if err != nil {
		return 0, fmt.Errorf("gp: SPI %q is not a 32-bit hex value", s)
	}
	return uint32(v), nil
}

func atoiOr(s string, def int) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return def
	}
	return n
}
