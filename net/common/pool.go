package common

import (
	"context"
	"errors"
	"log"
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

type ClientUtil struct {
	address string
	port    string
	host    string
	ip      bool
	cache   []net.IP
	lookUp  func(string) ([]net.IP, error)
}

func NewClientUtil(address, port string) ClientUtil {
	return ClientUtil{
		address: address,
		port:    port,
		host:    net.JoinHostPort(address, port),
		ip:      net.ParseIP(address) != nil,
		cache:   make([]net.IP, 1),
		lookUp: func(s string) ([]net.IP, error) {
			return LookupIP(net.DefaultResolver, s)
		},
	}
}
func (c *ClientUtil) dial() (net.Conn, error) {
	for ci := range c.cache {
		conn, err := net.Dial("tcp", net.JoinHostPort(c.cache[ci].String(), c.port))
		if err != nil {
			continue
		}
		return conn, nil
	}
	return nil, errors.New("vmess dial failed")
}

func (c *ClientUtil) GetConn() (net.Conn, error) {
	if c.ip {
		return net.Dial("tcp", c.host)
	}
	conn, err := c.dial()
	if err == nil {
		return conn, err
	}
	c.cache, err = c.lookUp(c.address)
	if err == nil {
		return c.dial()
	}
	return nil, err
}

func (c *ClientUtil) SetLookup(f func(string) ([]net.IP, error)) {
	if f == nil {
		log.Println("f is nil")
		return
	}

	c.lookUp = f
}
