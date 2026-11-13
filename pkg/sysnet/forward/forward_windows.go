package forward

import (
	"errors"
	"fmt"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// Manager applies forwarding plans on Windows by enabling forwarding on the
// ingress interfaces and the interfaces traffic may leave through. Windows
// has no policy routing, so forwarded traffic follows the routing table,
// including the System Network route rules; source filtering, per-rule
// egress and NAT are not available.
type Manager struct {
	links *LinkForwarding
}

func New() *Manager {
	return &Manager{links: &LinkForwarding{Get: getForwarding, Set: setForwarding}}
}

// Supported reports whether this platform has a forwarding applier.
func Supported() bool { return true }

func family(v6 bool) winipcfg.AddressFamily {
	if v6 {
		return windows.AF_INET6
	}
	return windows.AF_INET
}

func ipInterface(link int, v6 bool) (*winipcfg.MibIPInterfaceRow, error) {
	luid, err := winipcfg.LUIDFromIndex(uint32(link))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrLinkGone, err)
	}
	row, err := luid.IPInterface(family(v6))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrLinkGone, err)
	}
	return row, nil
}

func getForwarding(link int, v6 bool) (bool, error) {
	row, err := ipInterface(link, v6)
	if err != nil {
		return false, err
	}
	return row.ForwardingEnabled, nil
}

func setForwarding(link int, v6, on bool) error {
	row, err := ipInterface(link, v6)
	if err != nil {
		return err
	}
	row.ForwardingEnabled = on
	return row.Set()
}

func (m *Manager) Apply(plan Plan) error {
	want := map[int]bool{}
	for _, rule := range plan.Rules {
		if len(rule.Sources) != 0 || !rule.Egress.Routes || rule.Masquerade || rule.Egress.tproxy() {
			return errors.New("forwarding on Windows follows the routing table for every device on the ingress; source CIDRs, a per-rule egress and NAT are not supported")
		}
		want[rule.IngressLink] = true
	}
	if len(want) != 0 {
		for _, link := range plan.Links {
			want[link] = true
		}
	}
	return m.links.Apply(want, plan.IPv4, plan.IPv6)
}

func (m *Manager) Close() error { return m.links.Apply(nil, false, false) }
