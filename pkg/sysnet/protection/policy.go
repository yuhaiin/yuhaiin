// Package protection is Network Protection (the kill switch): it blocks
// Internet traffic that does not go through Yuhaiin, at the operating system
// level, and keeps blocking when Yuhaiin itself stops or crashes.
//
// The package is platform neutral. A Policy says what may pass; a Backend
// makes the operating system enforce it. The Controller builds the policy
// from the System Network Manager (private networks, explicit bypass routes,
// running Yuhaiin TUNs) and keeps the backend in sync. Platform mechanisms
// (the macOS packet filter, its anchors, utun names) stay inside backends.
package protection

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/contract/sysnet"
)

// Limits on policy size. They bound what a backend has to load and what the
// privileged service accepts from a client.
const (
	MaxNetworks = 65536
	MaxTunnels  = 16
)

// Policy is what Network Protection allows. Everything else that would leave
// the host towards the Internet is blocked.
//
// Mode, StartAtBoot, PrivateNetworks, BypassNetworks and the families are the
// persistent part: a backend keeps enforcing them while Yuhaiin is not
// running. Tunnels and OwnTraffic describe the running Yuhaiin process and are
// only honored while that process is connected to the backend, so a crashed
// process's TUN name or socket identity can never be reused by another
// program.
type Policy struct {
	Mode        string `json:"mode"`
	StartAtBoot bool   `json:"startAtBoot"`
	// PrivateNetworks may be reached directly (LAN, loopback, link-local).
	PrivateNetworks []netip.Prefix `json:"privateNetworks"`
	// BypassNetworks are destinations the user explicitly routes outside
	// Yuhaiin (System Network bypass CIDRs and routes to other interfaces).
	BypassNetworks []netip.Prefix `json:"bypassNetworks"`
	// Tunnels are the running Yuhaiin TUN interfaces.
	Tunnels []Tunnel `json:"tunnels,omitzero"`
	// OwnTraffic allows connections opened by the Yuhaiin process itself:
	// proxy servers, tunnel endpoints, bootstrap DNS and direct routes.
	OwnTraffic bool `json:"ownTraffic,omitzero"`
}

// Tunnel is a Yuhaiin TUN interface and the families it carries.
type Tunnel struct {
	Name string `json:"name"`
	IPv4 bool   `json:"ipv4"`
	IPv6 bool   `json:"ipv6"`
}

// Persistent returns the part of the policy that stays in force without a
// running Yuhaiin process.
func (p Policy) Persistent() Policy {
	p.Tunnels, p.OwnTraffic = nil, false
	return p
}

// Families reports which families a Yuhaiin tunnel carries.
func (p Policy) Families() (v4, v6 bool) {
	for _, t := range p.Tunnels {
		v4, v6 = v4 || t.IPv4, v6 || t.IPv6
	}
	return
}

var errEmptyName = errors.New("empty interface name")

// ValidInterfaceName accepts portable interface names: a letter, then
// letters, digits and a few separators, at most 15 bytes (IFNAMSIZ - 1).
// Backends may be stricter.
func ValidInterfaceName(name string) error {
	if name == "" {
		return errEmptyName
	}
	if len(name) > 15 {
		return fmt.Errorf("interface name %q is too long", name)
	}
	for i, r := range name {
		letter := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z'
		if i == 0 && !letter {
			return fmt.Errorf("invalid interface name %q", name)
		}
		if !letter && (r < '0' || r > '9') && r != '_' && r != '-' && r != '.' {
			return fmt.Errorf("invalid interface name %q", name)
		}
	}
	return nil
}

// Validate rejects a policy a backend must not load. It never repairs input:
// an invalid entry is an error, not silently dropped.
func (p Policy) Validate() error {
	if p.Mode != sysnet.ProtectionModeStandard {
		return fmt.Errorf("unsupported protection mode %q", p.Mode)
	}
	if err := validNetworks("private", p.PrivateNetworks, false); err != nil {
		return err
	}
	if err := validNetworks("bypass", p.BypassNetworks, true); err != nil {
		return err
	}
	if len(p.Tunnels) > MaxTunnels {
		return fmt.Errorf("too many tunnel interfaces: %d (maximum %d)", len(p.Tunnels), MaxTunnels)
	}
	seen := map[string]bool{}
	for _, t := range p.Tunnels {
		if err := ValidInterfaceName(t.Name); err != nil {
			return fmt.Errorf("tunnel: %w", err)
		}
		if seen[t.Name] {
			return fmt.Errorf("tunnel %q is listed twice", t.Name)
		}
		seen[t.Name] = true
	}
	return nil
}

func validNetworks(field string, list []netip.Prefix, bypass bool) error {
	if len(list) > MaxNetworks {
		return fmt.Errorf("too many %s networks: %d (maximum %d)", field, len(list), MaxNetworks)
	}
	for _, p := range list {
		switch {
		case !p.IsValid():
			return fmt.Errorf("invalid %s network", field)
		case p.Addr().Zone() != "":
			return fmt.Errorf("%s network %s: zones are not allowed", field, p)
		case p.Addr().Is4In6():
			return fmt.Errorf("%s network %s: use the IPv4 form", field, p)
		case p != p.Masked():
			return fmt.Errorf("%s network %s has host bits set", field, p)
		case bypass && p.Bits() == 0:
			// A default route is never an explicit bypass: allowing it
			// would switch the protection off.
			return fmt.Errorf("%s network %s would allow all traffic", field, p)
		}
	}
	return nil
}

// Normalize sorts and deduplicates every list, so equal policies compare and
// fingerprint equal regardless of the order their sources produced them in.
func (p Policy) Normalize() Policy {
	p.PrivateNetworks = sortPrefixes(p.PrivateNetworks)
	p.BypassNetworks = sortPrefixes(p.BypassNetworks)
	p.Tunnels = slices.Clone(p.Tunnels)
	slices.SortFunc(p.Tunnels, func(a, b Tunnel) int { return strings.Compare(a.Name, b.Name) })
	p.Tunnels = slices.CompactFunc(p.Tunnels, func(a, b Tunnel) bool { return a.Name == b.Name })
	return p
}

func sortPrefixes(list []netip.Prefix) []netip.Prefix {
	out := slices.Clone(list)
	slices.SortFunc(out, func(a, b netip.Prefix) int {
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c
		}
		return cmp.Compare(a.Bits(), b.Bits())
	})
	out = slices.Compact(out)
	if out == nil {
		out = []netip.Prefix{}
	}
	return out
}

// Fingerprint identifies a normalized policy. Two policies with the same
// fingerprint enforce the same thing, so an update can be skipped.
func (p Policy) Fingerprint() string {
	data, _ := json.Marshal(p.Normalize())
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// Diff describes what changes between two policies, for logs and status.
func Diff(old, new Policy) []string {
	old, new = old.Normalize(), new.Normalize()
	var out []string
	if old.Mode != new.Mode {
		out = append(out, fmt.Sprintf("mode %s -> %s", old.Mode, new.Mode))
	}
	if old.StartAtBoot != new.StartAtBoot {
		out = append(out, fmt.Sprintf("start at boot %v -> %v", old.StartAtBoot, new.StartAtBoot))
	}
	diffList := func(name string, a, b []netip.Prefix) {
		added, removed := 0, 0
		for _, p := range b {
			if _, ok := slices.BinarySearchFunc(a, p, comparePrefix); !ok {
				added++
			}
		}
		for _, p := range a {
			if _, ok := slices.BinarySearchFunc(b, p, comparePrefix); !ok {
				removed++
			}
		}
		if added+removed > 0 {
			out = append(out, fmt.Sprintf("%s +%d -%d", name, added, removed))
		}
	}
	diffList("private", old.PrivateNetworks, new.PrivateNetworks)
	diffList("bypass", old.BypassNetworks, new.BypassNetworks)
	if !slices.Equal(old.Tunnels, new.Tunnels) {
		out = append(out, fmt.Sprintf("tunnels %v -> %v", tunnelNames(old.Tunnels), tunnelNames(new.Tunnels)))
	}
	if old.OwnTraffic != new.OwnTraffic {
		out = append(out, fmt.Sprintf("own traffic %v -> %v", old.OwnTraffic, new.OwnTraffic))
	}
	return out
}

func comparePrefix(a, b netip.Prefix) int {
	if c := a.Addr().Compare(b.Addr()); c != 0 {
		return c
	}
	return cmp.Compare(a.Bits(), b.Bits())
}

func tunnelNames(list []Tunnel) []string {
	out := make([]string, len(list))
	for i, t := range list {
		out[i] = t.Name
	}
	return out
}

// PrefixStrings renders prefixes for status, at most limit of them.
func PrefixStrings(list []netip.Prefix, limit int) []string {
	out := make([]string, 0, min(len(list), limit))
	for i, p := range list {
		if i >= limit {
			break
		}
		out = append(out, p.String())
	}
	return out
}
