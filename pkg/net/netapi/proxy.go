package netapi

import (
	"context"
	"net"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/utils/lru"
)

type EmptyDispatch struct{}

func (EmptyDispatch) Dispatch(_ context.Context, a Address) (Address, error) { return a, nil }

type errProxy struct {
	EmptyDispatch
	error
}

func NewErrProxy(err error) Proxy                                              { return &errProxy{error: err} }
func (e errProxy) Conn(context.Context, Address) (net.Conn, error)             { return nil, e.error }
func (e errProxy) PacketConn(context.Context, Address) (net.PacketConn, error) { return nil, e.error }

type DynamicProxy struct {
	mu sync.RWMutex
	p  Proxy
}

func (d *DynamicProxy) Conn(ctx context.Context, a Address) (net.Conn, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.p.Conn(ctx, a)
}

func (d *DynamicProxy) PacketConn(ctx context.Context, a Address) (net.PacketConn, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.p.PacketConn(ctx, a)
}

func (d *DynamicProxy) Dispatch(ctx context.Context, a Address) (Address, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.p.Dispatch(ctx, a)
}

func (d *DynamicProxy) Set(p Proxy) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.p = p
}

func NewDynamicProxy(p Proxy) *DynamicProxy { return &DynamicProxy{p: p} }

var happyEyeballsCache = lru.New(lru.WithCapacity[string, net.IP](512))

func DialHappyEyeballs(ctx context.Context, addr Address) (net.Conn, error) {
	if !addr.IsFqdn() {
		return dialer.DialContext(ctx, "tcp", addr.String())
	}

	ips, err := LookupIP(ctx, addr)
	if err != nil {
		return nil, err
	}

	lastIP, ok := happyEyeballsCache.Load(addr.Hostname())

	tcpAddress := make([]*net.TCPAddr, 0, len(ips))
	for _, i := range ips {
		if ok && lastIP.Equal(i) && len(tcpAddress) > 0 {
			tmp := tcpAddress[0]
			tcpAddress[0] = &net.TCPAddr{IP: i, Port: tmp.Port}
			tcpAddress = append(tcpAddress, tmp)
		} else {
			tcpAddress = append(tcpAddress, &net.TCPAddr{IP: i, Port: int(addr.Port())})
		}
	}

	conn, err := dialer.DialHappyEyeballs(ctx, tcpAddress)
	if err != nil {
		return nil, err
	}

	connAddr, ok := conn.RemoteAddr().(*net.TCPAddr)
	if ok {
		happyEyeballsCache.Add(addr.Hostname(), connAddr.IP)
	}

	return conn, nil
}
