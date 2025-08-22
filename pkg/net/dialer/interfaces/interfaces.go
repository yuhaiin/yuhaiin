// get default route interface
// copy from https://github.com/tailscale/tailscale/blob/main/net/netmon
package interfaces

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/utils/atomicx"
	"github.com/Asutorufa/yuhaiin/pkg/utils/id"
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

func StartNetworkMonitor() networkMonitorCloser {
	log.Info("start network monitor")

	ctx, cancel := context.WithCancel(context.Background())

	var mu sync.Mutex
	go startMonitor(ctx, func() {
		mu.Lock()
		defer mu.Unlock()

		r, err := defaultRouteInterface()
		if err != nil {
			log.Error("DefaultRouteInterface", "err", err)
			return
		}

		old := defaultInterfaceName.Load()
		if r == "" || (old != nil && *old == r) {
			return
		}

		if !defaultInterfaceName.CompareAndSwap(old, &r) {
			return
		}

		log.Info("update default interface", "new", r, "old", atomicx.PointerOrEmpty(old))

		for _, v := range networkMonitors.Range {
			if v == nil {
				continue
			}

			v(r)
		}
	})

	return networkMonitorCloser(cancel)
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

func (i Interface) IsLoopback() bool { return i.Interface.Flags&net.FlagLoopback != 0 }
func (i Interface) IsUp() bool       { return i.Interface.Flags&net.FlagUp != 0 }
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
	ret := make([]Interface, len(ifs))
	for i := range ifs {
		ret[i].Interface = &ifs[i]
	}
	return ret, nil
}

type NetworkMonitor interface {
	Stop() error
}

var networkMonitors syncmap.SyncMap[id.UUID, func(interfaceName string)]

func AddNetworkMonitor(m func(interfaceName string)) io.Closer {
	uuid := id.GenerateUUID()
	networkMonitors.Store(uuid, m)

	return networkMonitorCloser(func() {
		networkMonitors.Delete(uuid)
	})
}
