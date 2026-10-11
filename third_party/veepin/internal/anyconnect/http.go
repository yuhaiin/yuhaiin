package anyconnect

import (
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
)

// HTTP paths in the exchange. The tunnel path is Cisco's and is what OpenConnect
// and ocserv both use.
const (
	authPath   = "/auth"
	tunnelPath = "/CSCOSSLC/tunnel"
)

// sessionCookie is the cookie name carrying the session token from the
// authentication exchange to the CONNECT request.
const sessionCookie = "webvpn"

// TunnelConfig is the addressing a server assigns a client. In AnyConnect this
// arrives as CONNECT response headers rather than through an in-tunnel
// negotiation, so it is fully known before the first packet moves.
type TunnelConfig struct {
	Address net.IP   // the client's inner address
	Netmask net.IP   // its netmask
	DNS     []net.IP // DNS servers to use over the tunnel
	MTU     int      // inner MTU
	// SplitInclude are the destinations routed into the tunnel. Empty means a
	// full tunnel, which is what the protocol says an absent header implies.
	SplitInclude []string
	// Domains are the search domains, space-separated as the header carries them.
	Domains string
}

// Header names carrying that configuration. The X-CSTP-* set is the server's
// reply; a client sends the request half to state what it can accept.
const (
	hdrVersion       = "X-CSTP-Version"
	hdrAddress       = "X-CSTP-Address"
	hdrNetmask       = "X-CSTP-Netmask"
	hdrDNS           = "X-CSTP-DNS"
	hdrMTU           = "X-CSTP-MTU"
	hdrBaseMTU       = "X-CSTP-Base-MTU"
	hdrAddressType   = "X-CSTP-Address-Type"
	hdrSplitInclude  = "X-CSTP-Split-Include"
	hdrDefaultDomain = "X-CSTP-Default-Domain"
	hdrDPD           = "X-CSTP-DPD"
	hdrKeepalive     = "X-CSTP-Keepalive"
	hdrDisconnected  = "X-CSTP-Disconnected-Timeout"
	hdrSessTimeout   = "X-CSTP-Session-Timeout"
	hdrIdleTimeout   = "X-CSTP-Idle-Timeout"
	hdrHostname      = "X-CSTP-Hostname"
	hdrLease         = "X-CSTP-Lease-Duration"
)

// Headers negotiating the optional DTLS data channel (RFC 5705 keying, see
// dtls.go). The client offers PSK-NEGOTIATE; a server that supports it answers
// with the port to use and an application identifier that ties the UDP flow back
// to this HTTPS session.
const (
	hdrDTLSCipherSuite = "X-DTLS-CipherSuite"
	hdrDTLSAppID       = "X-DTLS-App-ID"
	hdrDTLSPort        = "X-DTLS-Port"
	hdrDTLSDPD         = "X-DTLS-DPD"
	hdrDTLSKeepalive   = "X-DTLS-Keepalive"
	hdrDTLSMTU         = "X-DTLS-MTU"
)

// pskNegotiate is the cipher-suite token selecting the modern DTLS mode, in
// which the pre-shared key comes from an exporter on the TLS session rather than
// from a master secret the client ships in a header. veepin implements only this
// mode: the legacy Cisco scheme requires injecting a master secret into a DTLS
// session, which no ordinary DTLS implementation can do.
const pskNegotiate = "PSK-NEGOTIATE"

// dtlsExporterLabel and dtlsPSKLen are the RFC 5705 exporter parameters both
// ends use to derive the DTLS pre-shared key from the CSTP/TLS session
// (draft-mavrogiannopoulos-openconnect section 6). Deriving it means the UDP
// channel inherits the authentication of the HTTPS one, with nothing extra sent.
const (
	dtlsExporterLabel = "EXPORTER-openconnect-psk"
	dtlsPSKLen        = 32
)

// httpsPort is the port AnyConnect servers listen on, and the default the DTLS
// channel falls back to when the server names none of its own.
const httpsPort = 443

// DTLSParams is what a CONNECT response says about the UDP data channel. Enabled
// is false when the server did not offer one, in which case the tunnel simply
// stays on TLS.
type DTLSParams struct {
	Enabled bool
	Port    int
	AppID   []byte // hex-decoded; goes in the DTLS ClientHello's session-id
	MTU     int
}

// parseDTLSParams reads the DTLS offer from a CONNECT response. Anything other
// than PSK-NEGOTIATE is declined rather than half-supported.
func parseDTLSParams(h http.Header, tlsMTU int) (DTLSParams, error) {
	suite := h.Get(hdrDTLSCipherSuite)
	if suite == "" {
		return DTLSParams{}, nil
	}
	if !strings.Contains(strings.ToUpper(suite), "PSK") {
		return DTLSParams{}, fmt.Errorf("anyconnect: server offered DTLS suite %q, which is not %s", suite, pskNegotiate)
	}
	p := DTLSParams{Enabled: true, Port: httpsPort, MTU: tlsMTU}
	if v := h.Get(hdrDTLSPort); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 || n > 65535 {
			return DTLSParams{}, fmt.Errorf("anyconnect: server sent an unusable %s %q", hdrDTLSPort, v)
		}
		p.Port = n
	}
	if v := h.Get(hdrDTLSMTU); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			p.MTU = n
		}
	}
	if v := h.Get(hdrDTLSAppID); v != "" {
		id, err := hex.DecodeString(v)
		if err != nil {
			return DTLSParams{}, fmt.Errorf("anyconnect: server sent a non-hex %s", hdrDTLSAppID)
		}
		p.AppID = id
	}
	return p, nil
}

// defaultMTU is the inner MTU veepin assigns when acting as the server.
//
// Unlike the UDP protocols in this tree, this one cannot be derived exactly.
// The carrier is TLS over TCP, and TLS record overhead depends on the
// negotiated version and cipher suite: TLS 1.3 spends one content-type octet
// and a 16-octet tag, TLS 1.2 with AES-GCM spends an 8-octet explicit nonce and
// a 16-octet tag, and the DTLS path spends a different amount again. Worst case
// on a 1500-octet path:
//
//	1500 - 20 (IPv4) - 20 (TCP) - 5 (TLS record header)
//	     - 24 (explicit nonce + tag) - 8 (CSTP header) = 1423
//
// 1400 sits under that with room to spare, which is what Cisco's own servers
// hand out and therefore what clients expect. The margin absorbs TCP options —
// timestamps alone cost 12 octets — that the bound above ignores.
const defaultMTU = 1400

// buildConnectRequest renders the CONNECT that turns the authenticated HTTPS
// connection into a tunnel.
//
// It is written by hand for the same reason responses are: net/http canonicalizes
// header names, turning X-CSTP-MTU into X-Cstp-Mtu and X-DTLS-CipherSuite into
// X-Dtls-Ciphersuite. AnyConnect servers match these case-sensitively and
// silently ignore what they do not recognise, so a canonicalized DTLS offer reads
// to them as no offer at all — the tunnel still works, but only ever over TLS,
// which is precisely how this was missed until the UDP channel was implemented.
func buildConnectRequest(host, cookie, hostname string, baseMTU int) []byte {
	var h headerList
	h.set("Host", host)
	h.set("User-Agent", userAgent)
	h.set("Cookie", sessionCookie+"="+cookie)
	h.set(hdrVersion, "1")
	h.set(hdrHostname, hostname)
	h.setInt(hdrBaseMTU, baseMTU)
	h.setInt(hdrMTU, baseMTU)
	// IPv4 only: the data path forwards IPv4, so asking for an IPv6 address would
	// mean accepting one veepin cannot route.
	h.set(hdrAddressType, "IPv4")
	// Offer the UDP data channel. A server that does not support it simply omits
	// the DTLS headers from its reply and the tunnel stays on TLS.
	h.set(hdrDTLSCipherSuite, pskNegotiate)

	var buf []byte
	buf = append(buf, "CONNECT "+tunnelPath+" HTTP/1.1\r\n"...)
	for _, kv := range h {
		buf = append(buf, kv[0]...)
		buf = append(buf, ": "...)
		buf = append(buf, kv[1]...)
		buf = append(buf, "\r\n"...)
	}
	return append(buf, "\r\n"...)
}

// userAgent identifies veepin as an AnyConnect client. Servers parse this and
// some gate features on recognising the product name, so it follows the shape
// OpenConnect uses.
const userAgent = "AnyConnect-compatible veepin agent " + clientVersion

// parseTunnelConfig reads the addressing out of a CONNECT response's headers.
func parseTunnelConfig(h http.Header) (TunnelConfig, error) {
	var cfg TunnelConfig
	addr := h.Get(hdrAddress)
	if addr == "" {
		return cfg, fmt.Errorf("anyconnect: server assigned no address (%s missing)", hdrAddress)
	}
	cfg.Address = net.ParseIP(addr)
	if cfg.Address == nil {
		return cfg, fmt.Errorf("anyconnect: server sent an unparseable address %q", addr)
	}
	if mask := h.Get(hdrNetmask); mask != "" {
		cfg.Netmask = net.ParseIP(mask)
	}
	if cfg.Netmask == nil {
		cfg.Netmask = net.IPv4(255, 255, 255, 255)
	}
	// DNS servers arrive as repeated headers, and some servers instead comma-join
	// them into one, so both shapes are accepted.
	for _, v := range h.Values(hdrDNS) {
		for s := range strings.SplitSeq(v, ",") {
			if ip := net.ParseIP(strings.TrimSpace(s)); ip != nil {
				cfg.DNS = append(cfg.DNS, ip)
			}
		}
	}
	cfg.MTU = defaultMTU
	if v := h.Get(hdrMTU); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.MTU = n
		}
	}
	for _, v := range h.Values(hdrSplitInclude) {
		for s := range strings.SplitSeq(v, ",") {
			if s = strings.TrimSpace(s); s != "" {
				cfg.SplitInclude = append(cfg.SplitInclude, s)
			}
		}
	}
	cfg.Domains = h.Get(hdrDefaultDomain)
	return cfg, nil
}

// writeTunnelConfig renders a server's assignment as CONNECT response headers.
func writeTunnelConfig(h *headerList, cfg TunnelConfig, dpd, keepalive int) {
	h.set(hdrVersion, "1")
	h.set(hdrAddress, cfg.Address.String())
	h.set(hdrNetmask, cfg.Netmask.String())
	for _, ip := range cfg.DNS {
		h.add(hdrDNS, ip.String())
	}
	mtu := cfg.MTU
	if mtu == 0 {
		mtu = defaultMTU
	}
	h.setInt(hdrMTU, mtu)
	h.setInt(hdrBaseMTU, mtu)
	for _, r := range cfg.SplitInclude {
		h.add(hdrSplitInclude, r)
	}
	if cfg.Domains != "" {
		h.set(hdrDefaultDomain, cfg.Domains)
	}
	h.setInt(hdrDPD, dpd)
	h.setInt(hdrKeepalive, keepalive)
	// Zero disables each timeout: veepin holds a session for as long as its
	// connection lives rather than expiring it on a clock.
	h.set(hdrSessTimeout, "0")
	h.set(hdrIdleTimeout, "0")
	h.set(hdrDisconnected, "0")
	h.set(hdrLease, "0")
}
