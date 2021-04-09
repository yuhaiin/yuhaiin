package utils

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

var (
	//BuffPool byte array poll
	BuffPool = sync.Pool{
		New: func() interface{} {
			x := make([]byte, 16*0x400)
			return &x
		},
	}
)

//Forward pipe
func Forward(conn1, conn2 net.Conn) {
	go func() {
		buf := *BuffPool.Get().(*[]byte)
		defer BuffPool.Put(&(buf))
		_, _ = io.CopyBuffer(conn2, conn1, buf)
	}()
	buf := *BuffPool.Get().(*[]byte)
	defer BuffPool.Put(&(buf))
	_, _ = io.CopyBuffer(conn1, conn2, buf)
}

//SingleForward single pipe
func SingleForward(src io.Reader, dst io.Writer) (err error) {
	buf := *BuffPool.Get().(*[]byte)
	defer BuffPool.Put(&(buf))
	_, err = io.CopyBuffer(dst, src, buf)
	return
}

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
	cache   []string
	ip      bool

	dialer net.Dialer
	lock   sync.RWMutex
}

//NewClientUtil .
func NewClientUtil(address, port string) *ClientUtil {
	return &ClientUtil{
		address: address,
		port:    port,
		host:    net.JoinHostPort(address, port),
		dialer: net.Dialer{
			Timeout: time.Second * 10,
		},
		ip: net.ParseIP(address) != nil,
	}
}

func (c *ClientUtil) lookUp(s string) ([]net.IP, error) {
	return LookupIP(net.DefaultResolver, s)
}

func (c *ClientUtil) dial() (net.Conn, error) {
	c.lock.RLock()
	defer c.lock.RUnlock()
	for ci := range c.cache {
		conn, err := c.dialer.Dial("tcp", c.cache[ci])
		if err != nil {
			continue
		}
		return conn, nil
	}
	return nil, errors.New("dial failed")
}

//GetConn .
func (c *ClientUtil) GetConn() (net.Conn, error) {
	if c.ip {
		return c.dialer.Dial("tcp", c.host)
	}

	conn, err := c.dial()
	if err == nil {
		return conn, err
	}

	c.refreshCache()

	return c.dial()
}

func (c *ClientUtil) refreshCache() {
	x, err := c.lookUp(c.address)
	if err != nil {
		log.Printf("lookup address %s failed: %v", c.address, err)
	}
	cache := make([]string, 0, len(x))
	for i := range x {
		cache = append(cache, net.JoinHostPort(x[i].String(), c.port))
	}

	c.lock.Lock()
	defer c.lock.Unlock()

	c.cache = cache
}

//Unit .
type Unit int

var (
	//B .
	B Unit = 0
	//KB .
	KB Unit = 1
	//MB .
	MB Unit = 2
	//GB .
	GB Unit = 3
	//TB .
	TB Unit = 4
	//PB .
	PB Unit = 5
	//B2 .
	B2 = "B"
	//KB2 .
	KB2 = "KB"
	//MB2 .
	MB2 = "MB"
	//GB2 .
	GB2 = "GB"
	//TB2 .
	TB2 = "TB"
	//PB2 .
	PB2 = "PB"
)

//ReducedUnit .
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

//ReducedUnitStr .
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

type Proxy interface {
	Conn(string) (net.Conn, error)
	PacketConn(string) (net.PacketConn, error)
}

type DefaultProxy struct {
}

func (d *DefaultProxy) Conn(s string) (net.Conn, error) {
	return net.DialTimeout("tcp", s, 15*time.Second)
}
func (d *DefaultProxy) PacketConn(string) (net.PacketConn, error) {
	return net.ListenPacket("udp", "")
}
