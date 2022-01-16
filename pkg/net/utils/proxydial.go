package utils

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log/logasfmt"
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
	port    uint16
	host    string
	lock    sync.RWMutex

	lookupCache  []string
	refreshCache func()
	lookupIP     func(host string) ([]net.IP, error)
}

func WithLookupIP(f func(host string) ([]net.IP, error)) func(*ClientUtil) {
	return func(cu *ClientUtil) {
		cu.lookupIP = f
	}
}

//NewClientUtil .
func NewClientUtil(address, port string, opts ...func(*ClientUtil)) *ClientUtil {
	p, _ := strconv.ParseUint(port, 10, 16)
	c := &ClientUtil{
		address: address,
		port:    uint16(p),
		host:    net.JoinHostPort(address, port),
		lookupIP: func(host string) ([]net.IP, error) {
			return LookupIP(net.DefaultResolver, host)
		},
	}

	for i := range opts {
		opts[i](c)
	}

	if net.ParseIP(address) != nil {
		c.refreshCache = func() {}
		c.lookupCache = []string{net.JoinHostPort(address, port)}
	} else {
		c.refreshCache = c.refresh
	}

	return c
}

var clientDialer = net.Dialer{Timeout: time.Second * 10}

func (c *ClientUtil) dial() (net.Conn, error) {
	c.lock.RLock()
	defer c.lock.RUnlock()
	es := &errs{}
	for ci := range c.lookupCache {
		conn, err := clientDialer.DialContext(context.Background(), "tcp", c.lookupCache[ci])
		if err != nil {
			es.Add(err)
			continue
		}

		if x, ok := conn.(*net.TCPConn); ok {
			_ = x.SetKeepAlive(true)
		}

		return conn, nil
	}

	return nil, fmt.Errorf("dial failed: %w", es)
}

type errs struct {
	err []error
}

func (e *errs) Error() string {
	s := strings.Builder{}
	for i := range e.err {
		s.WriteString(e.err[i].Error())
		s.WriteByte('\n')
	}

	return s.String()
}

func (e *errs) Errors() []error {
	return e.err
}

func (e *errs) Add(err error) {
	if err == nil {
		return
	}
	e.err = append(e.err, err)
}

//GetConn .
func (c *ClientUtil) GetConn() (net.Conn, error) {
	r := 0

retry:
	conn, err := c.dial()
	if err == nil {
		return conn, err
	}

	if errors.Is(err, syscall.ECONNRESET) {
		if r <= 3 {
			logasfmt.Println("check connection reset by peer: ", err, "retry")
			r++
			goto retry
		}
		logasfmt.Println("direct return error:", err)
		return nil, err
	}

	c.refreshCache()

	return c.dial()
}

func (c *ClientUtil) Conn(host string) (net.Conn, error) {
	return c.GetConn()
}

func (c *ClientUtil) PacketConn(host string) (net.PacketConn, error) {
	return net.ListenPacket("udp", "")
}

func (c *ClientUtil) refresh() {
	c.lock.Lock()
	defer c.lock.Unlock()

	x, err := c.lookupIP(c.address)
	if err != nil {
		log.Printf("lookup address %s failed: %v", c.address, err)
		return
	}

	c.lookupCache = make([]string, 0, len(x))
	port := strconv.FormatUint(uint64(c.port), 10)
	for i := range x {
		c.lookupCache = append(c.lookupCache, net.JoinHostPort(x[i].String(), port))
	}
}
