package netlink

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"syscall"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// ScopedRouteManager keeps interface-scoped default routes so sockets bound
// to a physical interface (Socket Protection on macOS) can always leave
// through it. It owns only the routes it created and removes them on Close.
type ScopedRouteManager struct {
	ownTun func(string) bool

	mu      sync.Mutex
	planner *scopedPlanner
	owned   map[scopedKey]ownedScoped
	last    []ScopedRoute
	lastErr error
	closed  bool

	// Replaceable for tests.
	readRIB    func() ([]RIBRoute, error)
	interfaces func(ownTun func(string) bool) ([]ScopedInterface, error)
	write      func(op int, r ScopedRoute) error
}

// NewScopedRouteManager returns the manager; ownTun reports Yuhaiin's TUNs.
func NewScopedRouteManager(ownTun func(string) bool) *ScopedRouteManager {
	return &ScopedRouteManager{
		ownTun:     ownTun,
		planner:    newScopedPlanner(),
		owned:      map[scopedKey]ownedScoped{},
		readRIB:    darwinRIB,
		interfaces: darwinScopedInterfaces,
		write:      writeScopedDefault,
	}
}

// Reconcile rereads the routing table and creates or removes Yuhaiin's
// scoped defaults. It is called at start and on every network change.
func (m *ScopedRouteManager) Reconcile() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil
	}
	rib, err := m.readRIB()
	if err != nil {
		m.lastErr = fmt.Errorf("read routing table: %w", err)
		return m.lastErr
	}
	ifaces, err := m.interfaces(m.ownTun)
	if err != nil {
		m.lastErr = fmt.Errorf("list interfaces: %w", err)
		return m.lastErr
	}
	plan, create, remove := m.planner.plan(rib, ifaces, m.owned)
	var result error
	for _, r := range remove {
		key := scopedKey{r.Index, r.IPv6}
		if err := m.deleteOwned(rib, r); err != nil {
			result = errors.Join(result, err)
			continue
		}
		delete(m.owned, key)
	}
	for _, r := range create {
		key := scopedKey{r.Index, r.IPv6}
		err := m.write(unix.RTM_ADD, r)
		if errors.Is(err, unix.EEXIST) {
			// Someone installed it meanwhile; the next pass borrows it.
			err = nil
		} else if err == nil {
			var prefixes []netip.Prefix
			for _, i := range ifaces {
				if i.Index == r.Index {
					prefixes = familyPrefixes(i, r.IPv6)
				}
			}
			m.owned[key] = ownedScoped{gateway: r.Gateway, prefixes: prefixes}
			log.Info("installed interface-scoped default route", "interface", r.Interface, "gateway", r.Gateway, "ipv6", r.IPv6)
		}
		if err != nil {
			result = errors.Join(result, fmt.Errorf("scoped default on %s: %w", r.Interface, err))
			for i := range plan {
				if plan[i].Index == r.Index && plan[i].IPv6 == r.IPv6 {
					plan[i].State, plan[i].Reason = ScopedFailed, err.Error()
				}
			}
		}
	}
	m.last, m.lastErr = plan, result
	return result
}

// deleteOwned removes our scoped default only if the routing table still
// holds it with our gateway: XNU deletes by destination and scope alone.
func (m *ScopedRouteManager) deleteOwned(rib []RIBRoute, r ScopedRoute) error {
	def := defaultPrefix(r.IPv6)
	for _, e := range rib {
		if e.Index == r.Index && e.Scoped && e.Dst == def {
			if e.Gateway != r.Gateway {
				return nil // replaced by another owner
			}
			err := m.write(unix.RTM_DELETE, r)
			if errors.Is(err, unix.ESRCH) {
				return nil
			}
			if err == nil {
				log.Info("removed interface-scoped default route", "index", r.Index, "gateway", r.Gateway, "ipv6", r.IPv6)
			}
			return err
		}
	}
	return nil // gone with its interface
}

// Routes returns the last plan and its error.
func (m *ScopedRouteManager) Routes() ([]ScopedRoute, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]ScopedRoute(nil), m.last...), m.lastErr
}

// Close removes every scoped default this manager created.
func (m *ScopedRouteManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil
	}
	m.closed = true
	rib, err := m.readRIB()
	if err != nil {
		return err
	}
	var result error
	for key, o := range m.owned {
		if err := m.deleteOwned(rib, ScopedRoute{Index: key.index, IPv6: key.v6, Gateway: o.gateway}); err != nil {
			result = errors.Join(result, err)
			continue
		}
		delete(m.owned, key)
	}
	return result
}

func writeScopedDefault(op int, r ScopedRoute) error {
	return writeRouteFlags(defaultPrefix(r.IPv6), r.Gateway, op, r.Index, unix.RTF_IFSCOPE)
}

func darwinRIB() ([]RIBRoute, error) {
	raw, err := route.FetchRIB(unix.AF_UNSPEC, route.RIBTypeRoute, 0)
	if err != nil {
		return nil, err
	}
	msgs, err := route.ParseRIB(route.RIBTypeRoute, raw)
	if err != nil {
		return nil, err
	}
	var out []RIBRoute
	for _, m := range msgs {
		r, ok := m.(*route.RouteMessage)
		if !ok || len(r.Addrs) <= syscall.RTAX_NETMASK || r.Flags&(unix.RTF_LLINFO|unix.RTF_WASCLONED) != 0 {
			continue
		}
		dst := darwinIP(r.Addrs[syscall.RTAX_DST])
		if !dst.IsValid() {
			continue
		}
		bits := dst.BitLen()
		if mask := darwinIP(r.Addrs[syscall.RTAX_NETMASK]); mask.IsValid() {
			bits, _ = net.IPMask(mask.AsSlice()).Size()
		} else if r.Flags&unix.RTF_HOST == 0 {
			bits = 0
		}
		e := RIBRoute{Dst: netip.PrefixFrom(dst, bits), Index: r.Index, Scoped: r.Flags&unix.RTF_IFSCOPE != 0}
		if r.Flags&unix.RTF_GATEWAY != 0 {
			e.Gateway = darwinIP(r.Addrs[syscall.RTAX_GATEWAY]).WithZone("")
		}
		out = append(out, e)
	}
	return out, nil
}

func darwinScopedInterfaces(ownTun func(string) bool) ([]ScopedInterface, error) {
	list, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := make([]ScopedInterface, 0, len(list))
	for _, i := range list {
		s := ScopedInterface{
			Name: i.Name, Index: i.Index,
			Up:       i.Flags&net.FlagUp != 0,
			Loopback: i.Flags&net.FlagLoopback != 0,
			OwnTun:   ownTun != nil && ownTun(i.Name),
		}
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok {
				if ip, ok := netip.AddrFromSlice(n.IP); ok {
					bits, _ := n.Mask.Size()
					s.Prefixes = append(s.Prefixes, netip.PrefixFrom(ip.Unmap(), bits))
				}
			}
		}
		out = append(out, s)
	}
	return out, nil
}
