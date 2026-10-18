// get default route interface
// copy from https://github.com/tailscale/tailscale/blob/main/net/netmon
package interfaces

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"
	"uuid"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/trie/cidr"
	"github.com/Asutorufa/yuhaiin/pkg/utils/atomicx"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
)

// DefaultRouteDetails are the details about a default route returned
// by DefaultRoute.
type DefaultRouteDetails struct {
	// InterfaceName is the interface name. It must always be populated.
	// It's like "eth0" (Linux), "Ethernet 2" (Windows), "en0" (macOS).
	InterfaceName string

	// InterfaceDesc is populated on Windows at least. It's a
	// longer description, like "Red Hat VirtIO Ethernet Adapter".
	InterfaceDesc string

	// InterfaceIndex is like net.Interface.Index.
	// Zero means not populated.
	InterfaceIndex int

	// TODO(bradfitz): break this out into v4-vs-v6 once that need arises.
}

var ErrNoDefaultRoute = errors.New("no default route found")

// defaultRouteInterface is like DefaultRoute but only returns the
// interface name.
func defaultRouteInterface() (string, error) {
	dr, err := DefaultRoute()
	if err != nil {
		return "", err
	}
	return dr.InterfaceName, nil
}

var (
	defaultInterfaceName   atomic.Pointer[string]
	defaultInterfaceNameMu sync.Mutex
)

func SetDefaultInterfaceName(name string) {
	defaultInterfaceNameMu.Lock()
	defer defaultInterfaceNameMu.Unlock()
	defaultInterfaceName.Store(&name)
	lastNetworkState.Store(nil)
}

func DefaultInterfaceName() string {
	d := defaultInterfaceName.Load()
	if d != nil {
		return *d
	}

	defaultInterfaceNameMu.Lock()
	defer defaultInterfaceNameMu.Unlock()

	if d = defaultInterfaceName.Load(); d != nil {
		return *d
	}

	r, err := defaultRouteInterface()
	if err != nil {
		if err == errors.ErrUnsupported {
			r = ""
			defaultInterfaceName.Store(&r)
			return r
		}

		log.Error("get default route interface failed", "err", err)
		return ""
	}

	log.Info("update default interface", "new", r)

	if defaultInterfaceName.CompareAndSwap(d, &r) {
		return r
	}

	// Another goroutine won the race, load the value it stored.
	return *defaultInterfaceName.Load()
}

// networkState holds the parts of network state which require notifying
// interface listeners. Full routing-table changes still refresh DefaultRouter.
type networkState struct {
	name       string
	addresses  []string
	gateways   []string
}

var lastNetworkState atomic.Pointer[networkState]

func snapshotNetwork(name string, addrs map[netip.Addr]string, routes router) networkState {
	s := networkState{name: name}
	if name == "" {
		return s
	}
	for addr, iface := range addrs {
		if iface == name {
			s.addresses = append(s.addresses, addr.String())
		}
	}
	for _, r := range [][]rtInfo{routes.v4, routes.v6} {
		for _, entry := range r {
			if entry.OutputIface == name && entry.Dst.IsValid() && entry.Dst.Bits() == 0 {
				s.gateways = append(s.gateways, fmt.Sprintf("%s:%s", entry.Dst, entry.Gateway))
			}
		}
	}
	slices.Sort(s.addresses)
	slices.Sort(s.gateways)
	return s
}

func networkStateChanged(a, b networkState) bool {
	return a.name != b.name ||
		!slices.Equal(a.addresses, b.addresses) ||
		!slices.Equal(a.gateways, b.gateways)
}

func StartNetworkMonitor() networkMonitorCloser {
	log.Info("start network monitor")

	ctx, cancel := context.WithCancel(context.Background())
	events := make(chan string, 1)
	// Initial reconciliation matters when an event was missed before startup.
	events <- "startup"

	nm := startMonitor(func(reason string) {
		select {
		case <-ctx.Done():
		case events <- reason:
		default:
			// One pending event is enough: the monitor reads a fresh snapshot.
		}
	})

	go func() {
		defer func() {
			if err := nm.Stop(); err != nil {
				log.Error("stop network monitor failed", "err", err)
			}
		}()
		runNetworkMonitor(ctx, events, reGetDefaultInterface,
			750*time.Millisecond, 5*time.Second, time.Minute)
	}()

	return networkMonitorCloser(cancel)
}

// runNetworkMonitor owns its timer. Route socket callbacks never Reset it.
// Continuous events must not postpone a refresh beyond maxWait.
func runNetworkMonitor(
	ctx context.Context,
	events <-chan string,
	refresh func(string) error,
	debounce, maxWait, poll time.Duration,
) {
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	defer timer.Stop()
	ticker := time.NewTicker(poll)
	defer ticker.Stop()

	var timerCh <-chan time.Time
	var firstEvent time.Time
	var reason string
	pending := false
	retries := 0

	schedule := func(d time.Duration) {
		if timerCh != nil {
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		}
		if d < 0 {
			d = 0
		}
		timer.Reset(d)
		timerCh = timer.C
	}
	apply := func(why string) {
		if err := refresh(why); err != nil {
			log.Error("refresh network state failed", "err", err, "reason", why)
			if retries < 3 {
				retries++
				pending = true
				firstEvent = time.Now()
				reason = "retry"
				schedule(5 * time.Second)
			}
			return
		}
		retries = 0
	}

	for {
		select {
		case <-ctx.Done():
			return
		case r, ok := <-events:
			if !ok {
				return
			}
			if !pending {
				firstEvent = time.Now()
				pending = true
			}
			reason = r
			delay := debounce
			if remaining := time.Until(firstEvent.Add(maxWait)); delay > remaining {
				delay = remaining
			}
			schedule(delay)
		case <-timerCh:
			timerCh = nil
			pending = false
			apply(reason)
		case <-ticker.C:
			if !pending {
				apply("periodic")
			}
		}
	}
}

func reGetDefaultInterface(reason string) error {
	// Collect all observations before publishing any of them. A transient
	// failure must not produce a mixed old/new cache.
	routes, err := routes()
	if err != nil {
		return fmt.Errorf("get routes failed: %w", err)
	}
	addresses, err := getLocalAddresses()
	if err != nil {
		return fmt.Errorf("get local addresses failed: %w", err)
	}
	name, err := defaultRouteInterface()
	if errors.Is(err, ErrNoDefaultRoute) {
		name = ""
	} else if err != nil {
		return fmt.Errorf("get default route interface failed: %w", err)
	}

	next := snapshotNetwork(name, addresses, routes)
	defaultInterfaceNameMu.Lock()
	old := defaultInterfaceName.Load()
	oldName := atomicx.PointerOrEmpty(old)
	prev := lastNetworkState.Load()
	changed := oldName != name || (prev != nil && networkStateChanged(*prev, next))
	defaultrouter.Store(routes.ToTrie())
	localAddresses.Store(&addresses)
	defaultInterfaceName.Store(&name)
	lastNetworkState.Store(&next)
	defaultInterfaceNameMu.Unlock()

	if !changed {
		return nil
	}
	log.Info("network state changed", "new", name, "old", oldName, "reason", reason)
	for _, notify := range networkMonitors.Range {
		if notify != nil {
			notify(name)
		}
	}
	return nil
}

type networkMonitorCloser func()

func (f networkMonitorCloser) Close() error {
	f()
	return nil
}

// DefaultRoute returns details of the network interface that owns
// the default route, not including any tailscale interfaces.
func DefaultRoute() (DefaultRouteDetails, error) {
	return defaultRoute()
}

// Interface is a wrapper around Go's net.Interface with some extra methods.
type Interface struct {
	*net.Interface
	AltAddrs []net.Addr // if non-nil, returned by Addrs
}

func (i Interface) IsLoopback() bool { return i.Flags&net.FlagLoopback != 0 }
func (i Interface) IsUp() bool       { return i.Flags&net.FlagUp != 0 }
func (i Interface) Addrs() ([]net.Addr, error) {
	if i.AltAddrs != nil {
		return i.AltAddrs, nil
	}
	return i.Interface.Addrs()
}

var AltNetInterfaces func() ([]Interface, error)

// GetInterfaceList returns the list of interfaces on the machine.
func GetInterfaceList() ([]Interface, error) {
	if AltNetInterfaces != nil {
		return AltNetInterfaces()
	}

	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	ret := make([]Interface, 0, len(ifs))
	for i := range ifs {
		ret = append(ret, Interface{Interface: &ifs[i]})
	}

	return ret, nil
}

type NetworkMonitor interface {
	Stop() error
}

var networkMonitors syncmap.SyncMap[uuid.UUID, func(interfaceName string)]

func AddNetworkMonitor(m func(interfaceName string)) io.Closer {
	uuid := uuid.New()
	networkMonitors.Store(uuid, m)

	return networkMonitorCloser(func() {
		networkMonitors.Delete(uuid)
	})
}

var (
	localAddresses   atomic.Pointer[map[netip.Addr]string]
	localAddressesMu sync.Mutex
)

func LocalAddresses() map[netip.Addr]string {
	x := localAddresses.Load()
	if x != nil {
		return *x
	}

	localAddressesMu.Lock()
	defer localAddressesMu.Unlock()

	x = localAddresses.Load()
	if x != nil {
		return *x
	}

	xx, err := getLocalAddresses()
	if err != nil {
		log.Warn("get local addresses failed", "err", err)
		return map[netip.Addr]string{}
	}

	if localAddresses.CompareAndSwap(nil, &xx) {
		return xx
	}
	return *localAddresses.Load()
}

func getLocalAddresses() (map[netip.Addr]string, error) {
	ifs, err := GetInterfaceList()
	if err != nil {
		return nil, err
	}

	ret := map[netip.Addr]string{}

	for _, v := range ifs {
		address, err := v.Addrs()
		if err != nil {
			log.Warn("get interface address failed", "err", err)
			continue
		}

		for _, a := range address {
			ipNet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}

			netip, ok := netip.AddrFromSlice(ipNet.IP)
			if !ok {
				continue
			}

			ret[netip.Unmap()] = v.Name
		}
	}

	return ret, nil
}

var (
	defaultrouter   atomic.Pointer[cidr.Cidr[string]]
	defaultrouterMu sync.Mutex
)

func DefaultRouter() *cidr.Cidr[string] {
	if x := defaultrouter.Load(); x != nil {
		return x
	}

	defaultrouterMu.Lock()
	defer defaultrouterMu.Unlock()

	if x := defaultrouter.Load(); x != nil {
		return x
	}

	rs, err := routes()
	if err != nil {
		log.Error("get default router failed", "err", err)
		return cidr.NewTrie[string]()
	}

	trie := rs.ToTrie()
	if defaultrouter.CompareAndSwap(nil, trie) {
		return trie
	}
	return defaultrouter.Load()
}
