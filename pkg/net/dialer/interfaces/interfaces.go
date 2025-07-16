// get default route interface
// copy from https://github.com/tailscale/tailscale/blob/main/net/netmon
package interfaces

import "net"

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

// DefaultRouteInterface is like DefaultRoute but only returns the
// interface name.
func DefaultRouteInterface() (string, error) {
	dr, err := DefaultRoute()
	if err != nil {
		return "", err
	}
	return dr.InterfaceName, nil
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
