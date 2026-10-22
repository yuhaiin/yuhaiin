package app

import (
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"

	"github.com/Asutorufa/yuhaiin/pkg/httpapi"
)

// The official static UI is a built-in trusted origin. Additional origins are
// opt-in settings; no remote web site can add itself without passing this guard.
const officialGatewayUIOrigin = "https://yuhaiin.github.io"

type managementOriginPolicy struct {
	custom atomic.Pointer[[]string]
}

func newManagementOriginPolicy() *managementOriginPolicy {
	p := &managementOriginPolicy{}
	p.set(nil)
	return p
}

func (p *managementOriginPolicy) set(origins []string) {
	copyOf := slices.Clone(origins)
	p.custom.Store(&copyOf)
}

// Exact origin comparison is important: suffix matching would trust attacker-
// controlled hosts such as yuhaiin.github.io.evil.example.
func (p *managementOriginPolicy) accepts(origin string, r *http.Request) bool {
	if origin == officialGatewayUIOrigin || localBrowserOrigin(origin) {
		return true
	}
	if p == nil {
		return false
	}
	current := p.custom.Load()
	return current != nil && slices.Contains(*current, origin)
}

func (p *managementOriginPolicy) authorize(auth *Auth, r *http.Request) bool {
	peer, err := netip.ParseAddrPort(r.RemoteAddr)
	localPeer := err == nil && peer.Addr().Unmap().IsLoopback()
	// A trusted browser origin is not user authentication: remote network peers
	// still need Basic credentials, including for requests without Origin.
	if !localPeer && auth == nil {
		return false
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true // CLI/native clients; subject to peer and Basic checks.
	}
	return p.accepts(origin, r) || (!localPeer && auth != nil && sameRequestOrigin(origin, r))
}

func localBrowserOrigin(origin string) bool {
	u, err := url.Parse(origin)
	if err != nil || u == nil || !validOriginURL(u, origin) {
		return false
	}
	host := u.Hostname()
	ip, ipErr := netip.ParseAddr(host)
	return strings.EqualFold(host, "localhost") || (ipErr == nil && ip.Unmap().IsLoopback())
}

func sameRequestOrigin(origin string, r *http.Request) bool {
	u, err := url.Parse(origin)
	if err != nil || u == nil || !validOriginURL(u, origin) || !strings.EqualFold(u.Host, r.Host) {
		return false
	}
	scheme := "http"
	if httpapi.ManagementHTTPS(r) {
		scheme = "https"
	}
	return u.Scheme == scheme
}

func validOriginURL(u *url.URL, raw string) bool {
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	// An Origin is only scheme://host[:port], never a path, userinfo,
	// query, fragment, "null", wildcard, or a serialized origin list.
	return u.Host != "" && u.Hostname() != "" &&
		!strings.ContainsAny(u.Hostname(), "* \t\r\n\\") && u.User == nil &&
		u.Opaque == "" && u.Path == "" && u.RawPath == "" &&
		u.RawQuery == "" && u.Fragment == "" && u.String() == raw
}

func validateTrustedOrigins(origins []string) error {
	if len(origins) > 32 {
		return fmt.Errorf("trusted origins: too many entries (maximum 32)")
	}
	seen := make(map[string]struct{}, len(origins))
	for _, origin := range origins {
		if len(origin) > 512 {
			return fmt.Errorf("trusted origin is too long")
		}
		u, err := url.Parse(origin)
		if err != nil || u == nil || !validOriginURL(u, origin) {
			return fmt.Errorf("invalid trusted origin %q: use a full http(s) origin without path", origin)
		}
		if u.Scheme != "https" && !localBrowserOrigin(origin) {
			return fmt.Errorf("trusted origin %q: non-local origins require HTTPS", origin)
		}
		if _, ok := seen[origin]; ok {
			return fmt.Errorf("duplicate trusted origin %q", origin)
		}
		seen[origin] = struct{}{}
	}
	return nil
}

func handleRPCFunc(mux *http.ServeMux, auth *Auth, policy *managementOriginPolicy, path string, next func(http.ResponseWriter, *http.Request) error) {
	handleFunc(mux, auth, policy, path, next)
}
