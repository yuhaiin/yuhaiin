package native

import (
	"errors"
	"net/netip"
	"slices"
)

// Config describes a client LAC (v2) or an Ethernet LCCE (v3) over UDP.
// Static v3 sessions use prearranged IDs and cookies without control messages.
type Config struct {
	AuthType                                            string
	Version                                             int
	Gateway, Hostname, Username, Password, SharedSecret string
	MTU                                                 int
	IPv6                                                bool
	IPv6Address                                         string
	Static                                              bool
	LocalSessionID, PeerSessionID                       uint32
	LocalCookie, PeerCookie                             []byte
	Sublayer                                            bool
	RemoteEndID                                         string
}

func (c *Config) Validate() error {
	if c.AuthType == "" {
		c.AuthType = "auto"
	}
	if !slices.Contains([]string{"auto", "pap", "chap-md5", "mschap-v2"}, c.AuthType) {
		return errors.New("l2tp: unsupported PPP authentication type")
	}
	if c.Version != 2 && c.Version != 3 {
		return errors.New("l2tp: version must be 2 or 3")
	}
	if c.Hostname == "" {
		c.Hostname = "yuhaiin"
	}
	if len(c.Hostname) > 255 || len(c.Username) > 255 || len(c.Password) > 255 || len(c.SharedSecret) > 255 {
		return errors.New("l2tp: identity/secret exceeds 255 bytes")
	}
	if c.MTU == 0 {
		c.MTU = 1400
	}
	if c.MTU < 576 || c.MTU > 1500 || c.IPv6 && c.MTU < 1280 {
		return errors.New("l2tp: MTU must be 576..1500 (at least 1280 for IPv6)")
	}
	if c.Version == 2 && c.Static {
		return errors.New("l2tp: static sessions require v3")
	}
	if c.Static && (c.LocalSessionID == 0 || c.PeerSessionID == 0) {
		return errors.New("l2tpv3: static session IDs must be nonzero")
	}
	for _, cookie := range [][]byte{c.LocalCookie, c.PeerCookie} {
		if len(cookie) != 0 && len(cookie) != 4 && len(cookie) != 8 {
			return errors.New("l2tpv3: cookie must be 0, 4 or 8 bytes")
		}
	}
	if len(c.RemoteEndID) > 255 {
		return errors.New("l2tpv3: remote end ID exceeds 255 bytes")
	}
	if c.IPv6Address != "" {
		p, err := netip.ParsePrefix(c.IPv6Address)
		if err != nil || !p.Addr().Is6() || p.Addr().IsUnspecified() || p.Addr().IsMulticast() {
			return errors.New("l2tp: invalid IPv6 prefix")
		}
		c.IPv6 = true
	}
	if c.IPv6 && c.MTU < 1280 {
		return errors.New("l2tp: IPv6 requires an MTU of at least 1280")
	}
	return nil
}

type Info struct {
	Prefixes                                                   []netip.Prefix
	DNS                                                        []string
	PeerAddress, Auth                                          string
	MTU                                                        int
	LocalTunnelID, PeerTunnelID, LocalSessionID, PeerSessionID uint32
}
