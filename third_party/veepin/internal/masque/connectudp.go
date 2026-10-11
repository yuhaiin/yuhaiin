package masque

// CONNECT-UDP (RFC 9298): proxying a single UDP flow through HTTP/3.
//
// Where CONNECT-IP carries whole IP packets and negotiates an address,
// CONNECT-UDP carries the payload of one UDP flow to a fixed target named in the
// request path. It shares the entire capsule and HTTP-Datagram machinery with
// CONNECT-IP -- the context-0 payload is byte-identical, only its contents differ
// (a raw UDP payload rather than an IP packet) -- so this file is just the path
// template, the request headers, and pulling the target back out of the path.

import (
	"net/url"
	"strconv"
	"strings"

	"github.com/xen0bit/veepin/internal/masque/http3"
)

// connectUDPProtocol is the :protocol token that turns an Extended CONNECT into
// a UDP-proxying flow (RFC 9298 §3).
const connectUDPProtocol = "connect-udp"

// ConnectUDPPath builds the request path from the URI template
// /.well-known/masque/udp/{target_host}/{target_port}/ (RFC 9298 §3). An IPv6
// literal host has its colons percent-encoded, as the template requires.
func ConnectUDPPath(host string, port int) string {
	return "/.well-known/masque/udp/" + url.PathEscape(host) + "/" + strconv.Itoa(port) + "/"
}

// ConnectUDPHeaders builds the pseudo-header set for a CONNECT-UDP request.
func ConnectUDPHeaders(authority, path string) []http3.Field {
	return []http3.Field{
		{Name: ":method", Value: "CONNECT"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: authority},
		{Name: ":path", Value: path},
		{Name: ":protocol", Value: connectUDPProtocol},
		{Name: "capsule-protocol", Value: "?1"},
	}
}

// IsConnectUDP reports whether a decoded request is a CONNECT-UDP request.
func IsConnectUDP(fields []http3.Field) bool {
	var method, protocol string
	for _, f := range fields {
		switch f.Name {
		case ":method":
			method = f.Value
		case ":protocol":
			protocol = f.Value
		}
	}
	return method == "CONNECT" && protocol == connectUDPProtocol
}

// ParseConnectUDPTarget extracts the target host and port from a CONNECT-UDP
// request path. It returns ok=false for a path that is not the expected template
// or whose port is not a number in range -- both of which the server answers
// with a 4xx rather than opening a socket to something it misread.
func ParseConnectUDPTarget(path string) (host string, port int, ok bool) {
	// Expected: /.well-known/masque/udp/{host}/{port}/
	const prefix = "/.well-known/masque/udp/"
	if !strings.HasPrefix(path, prefix) {
		return "", 0, false
	}
	rest := strings.TrimPrefix(path, prefix)
	rest = strings.TrimSuffix(rest, "/")
	parts := strings.Split(rest, "/")
	if len(parts) != 2 {
		return "", 0, false
	}

	h, err := url.PathUnescape(parts[0])
	if err != nil || h == "" {
		return "", 0, false
	}
	p, err := strconv.Atoi(parts[1])
	if err != nil || p < 1 || p > 65535 {
		return "", 0, false
	}
	return h, p, true
}
