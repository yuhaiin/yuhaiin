//go:build !linux || android

package netlink

import "net/netip"

type ProtectionRule struct {
	IPv6     bool
	Priority int
	Table    int
	Selector string

	Present, Old, Foreign bool
}

// ProtectionRules: only Linux protects sockets with policy routing.
func ProtectionRules() ([]ProtectionRule, error) { return nil, nil }

func MainRoutesVia([]int) ([]netip.Prefix, error) { return nil, nil }
