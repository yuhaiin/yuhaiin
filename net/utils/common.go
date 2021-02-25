package utils

import (
	"context"
	"errors"
	"fmt"
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

//ClientUtil .
type ClientUtil struct {
	address string
	port    string
	host    string
	ip      bool
	cache   []net.IP
	lookUp  func(string) ([]net.IP, error)
}

//NewClientUtil .
func NewClientUtil(address, port string) ClientUtil {
	return ClientUtil{
		address: address,
		port:    port,
		host:    net.JoinHostPort(address, port),
		ip:      net.ParseIP(address) != nil,
		cache:   make([]net.IP, 0, 1),
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

//GetConn .
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

//SetLookup set dns lookup
func (c *ClientUtil) SetLookup(f func(string) ([]net.IP, error)) {
	if f == nil {
		log.Println("f is nil")
		return
	}

	c.lookUp = f
}

type Unit int

var (
	B   Unit = 0
	KB  Unit = 1
	MB  Unit = 2
	GB  Unit = 3
	TB  Unit = 4
	PB  Unit = 5
	B2       = "B"
	KB2      = "KB"
	MB2      = "MB"
	GB2      = "GB"
	TB2      = "TB"
	PB2      = "PB"
)

func ReducedUnit(byte float64) (result float64, unit Unit) {
	if byte > 1125899906842624 {
		return byte / 1125899906842624, PB //PB
	}
	if byte > 1099511627776 {
		return byte / 1099511627776, TB //TB
	}
	if byte > 1073741824 {
		return byte / 1073741824, GB //GB
	}
	if byte > 1048576 {
		return byte / 1048576, MB //MB
	}
	if byte > 1024 {
		return byte / 1024, KB //KB
	}
	return byte, B //B
}

func ReducedUnitStr(byte float64) (result string) {
	if byte > 1125899906842624 {
		return fmt.Sprintf("%.2f%s", byte/1125899906842624, PB2) //PB
	}
	if byte > 1099511627776 {
		return fmt.Sprintf("%.2f%s", byte/1099511627776, TB2) //TB
	}
	if byte > 1073741824 {
		return fmt.Sprintf("%.2f%s", byte/1073741824, GB2) //GB
	}
	if byte > 1048576 {
		return fmt.Sprintf("%.2f%s", byte/1048576, MB2) //MB
	}
	if byte > 1024 {
		return fmt.Sprintf("%.2f%s", byte/1024, KB2) //KB
	}
	return fmt.Sprintf("%.2f%s", byte, B2) //B
}
