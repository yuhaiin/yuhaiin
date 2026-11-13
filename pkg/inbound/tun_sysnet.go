package inbound

import (
	"net/netip"
	"slices"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	contract "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun"
	"github.com/Asutorufa/yuhaiin/pkg/sysnet"
)

// SystemNetwork owns every system route; TUN inbounds only report their
// devices to it. *sysnet.Manager implements it.
type SystemNetwork interface {
	AttachTun(sysnet.TunAttachment)
	DetachTun(inboundID string)
	PlatformRoutes(inboundID string, ipv4, ipv6 bool) ([]netip.Prefix, bool)
}

// WithSystemNetwork connects running TUNs to the System Network Manager.
// Without it TUNs run with no routes.
func WithSystemNetwork(manager SystemNetwork) Option {
	return func(l *Inbound) { l.sysnet = manager }
}

type tunLinker interface{ TunLink() tun.Link }

// fakeIPRequired returns the FakeIP pools a TUN needs routed to itself.
func fakeIPRequired(config contract.TunProtocol, ranges [2]netip.Prefix) []netip.Prefix {
	if !config.AutoFakeIPRoute {
		return nil
	}
	var out []netip.Prefix
	for _, p := range ranges {
		if p.IsValid() && (p.Addr().Is4() || configuration.IPv6.Load()) {
			out = append(out, p.Masked())
		}
	}
	return out
}

// attachTun reports a started TUN. l.mu is held.
func (l *Inbound) attachTun(key string, config contract.Inbound, server netapi.Accepter) {
	if l.sysnet == nil || config.Protocol.Tun == nil {
		return
	}
	switch s := server.(type) {
	case tunLinker:
		link := s.TunLink()
		if link.Index == 0 {
			// fd:// devices have host-managed routes.
			return
		}
		required := append(slices.Clone(link.RequiredRoutes), fakeIPRequired(*config.Protocol.Tun, l.fakeIPRanges)...)
		l.sysnet.AttachTun(sysnet.TunAttachment{InboundID: key, InboundName: config.Name, Interface: link.Name, Index: link.Index,
			IPv4: link.IPv4.IsValid(), IPv6: link.IPv6.IsValid() && configuration.IPv6.Load(), Required: required})
	case *platformTunAccepter:
		l.sysnet.AttachTun(sysnet.TunAttachment{InboundID: key, InboundName: config.Name, Interface: "VPN", IPv4: true,
			IPv6: configuration.IPv6.Load(), Platform: s.setRoutes})
	default:
		return
	}
	if l.attached == nil {
		l.attached = map[netapi.Accepter]string{}
	}
	l.attached[server] = key
}

// detachTun removes a TUN's routes before it closes. l.mu is held.
func (l *Inbound) detachTun(server netapi.Accepter) {
	if id, ok := l.attached[server]; ok {
		delete(l.attached, server)
		l.sysnet.DetachTun(id)
	}
}

func prefixStrings(p []netip.Prefix) []string {
	out := make([]string, len(p))
	for i, x := range p {
		out[i] = x.String()
	}
	return out
}

// withoutLegacyRoutes drops TUN route fields that only the System Network
// migration reads.
func withoutLegacyRoutes(in contract.Inbound) contract.Inbound {
	return sysnet.ClearLegacyRouting(in)
}

// platformRoutes returns the System Network routes a platform TUN starts
// with, so its first interface already carries them. l.mu is held.
func (l *Inbound) platformRoutes(key string) ([]string, bool) {
	if l.sysnet == nil {
		return nil, false
	}
	routes, managed := l.sysnet.PlatformRoutes(key, true, configuration.IPv6.Load())
	return prefixStrings(routes), managed
}
