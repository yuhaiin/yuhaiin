package tun2socket

import (
	"net"
)

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
