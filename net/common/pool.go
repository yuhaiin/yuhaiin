package common

import (
	"context"
	"net"
	"sync"
)

var (
	BuffPool     = sync.Pool{New: func() interface{} { return make([]byte, 32*0x400) }}
	CloseSigPool = sync.Pool{New: func() interface{} { return make(chan error, 2) }}
	QueuePool    = sync.Pool{New: func() interface{} { return [2]uint64{} }}
)

// LookupIP looks up host using the local resolver.
// It returns a slice of that host's IPv4 and IPv6 addresses.
func LookupIP(resolver *net.Resolver, host string) ([]net.IP, error) {
	addrs, err := resolver.LookupIPAddr(context.Background(), host)
	if err != nil {
		return nil, err
	}
	ips := make([]net.IP, len(addrs))
	for i, ia := range addrs {
		ips[i] = ia.IP
	}
	return ips, nil
}
