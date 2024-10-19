package route

import (
	"net"
	"net/netip"
	"os"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
)

var myPath string

func init() {
	myPath, _ = os.Executable()
}

type LoopbackDetector struct {
	connStore syncmap.SyncMap[netip.AddrPort, struct{}]
}

func NewLoopback() *LoopbackDetector {
	return &LoopbackDetector{}
}

func (l *LoopbackDetector) IsLoopback(path string) bool {
	return path == myPath
}

func (l *LoopbackDetector) Cycle(meta *netapi.Context, addr netapi.Address) bool {
	if meta.Inbound == nil {
		return false
	}

	inbound, err := netapi.ParseSysAddr(meta.Inbound)
	if err != nil {
		return false
	}

	return inbound.Equal(addr)
}

func (l *LoopbackDetector) NewConn(conn net.Conn) net.Conn {
	localAddr, err := netapi.ParseSysAddr(conn.LocalAddr())
	if err != nil {
		return conn
	}

	if localAddr.IsFqdn() {
		return conn
	}

	key := netip.AddrPortFrom(localAddr.(*netapi.IPAddr).Addr, localAddr.Port())
	l.connStore.Store(key, struct{}{})

	return NewWrapCloseConn(conn, func() { l.connStore.Delete(key) })
}

type wrapCloseConn struct {
	net.Conn
	f func()
}

func NewWrapCloseConn(conn net.Conn, f func()) net.Conn {
	return &wrapCloseConn{
		Conn: conn,
		f:    f,
	}
}

func (w *wrapCloseConn) Close() error {
	w.f()
	return w.Conn.Close()
}

func (l *LoopbackDetector) CheckConnLoopback(meta *netapi.StreamMeta) bool {
	srcAddr, err := netapi.ParseSysAddr(meta.Source)
	if err != nil {
		return false
	}

	if srcAddr.IsFqdn() {
		return false
	}

	key := netip.AddrPortFrom(srcAddr.(*netapi.IPAddr).Addr, srcAddr.Port())
	_, ok := l.connStore.Load(key)

	return ok
}
