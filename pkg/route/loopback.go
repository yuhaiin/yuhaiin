package route

import (
	"net"
	"net/netip"
	"os"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
)

var myPath string
var myPid uint

func init() {
	myPath, _ = os.Executable()
	myPath = convertVolumeName(myPath)
	myPid = uint(os.Getpid())
}

type LoopbackDetector struct {
	connStore syncmap.SyncMap[netip.AddrPort, struct{}]
}

func NewLoopback() *LoopbackDetector {
	return &LoopbackDetector{}
}

func (l *LoopbackDetector) IsLoopback(ctx *netapi.Context, path string, pid uint) bool {
	var True bool

	// skip for test ownself latency?
	if ctx.GetFakeIP() == nil && ctx.GetHosts() == nil {
		ad, err := netapi.ParseSysAddr(ctx.Destination)
		if err == nil && ad.IsFqdn() {
			return false
		}
	}

	if myPath != "" {
		True = True || path == myPath
	}

	if True && myPath != "" && pid != 0 && myPid != 0 {
		True = True && pid == myPid
	}

	return True
}

func (l *LoopbackDetector) Cycle(meta *netapi.Context, addr netapi.Address) bool {
	if meta.GetInbound() == nil {
		return false
	}

	inbound, err := netapi.ParseSysAddr(meta.GetInbound())
	if err != nil {
		return false
	}

	return inbound.Comparable() == addr.Comparable()
}

func (l *LoopbackDetector) NewConn(conn net.Conn) net.Conn {
	localAddr, err := netapi.ParseSysAddr(conn.LocalAddr())
	if err != nil {
		return conn
	}

	if localAddr.IsFqdn() {
		return conn
	}

	key := localAddr.(netapi.IPAddr).AddrPort()
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

	key := srcAddr.(netapi.IPAddr).AddrPort()
	_, ok := l.connStore.Load(key)

	return ok
}
