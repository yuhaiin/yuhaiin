package nat

import (
	"context"
	"errors"
	"io"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestTable(t *testing.T) {
	tp := &testProxy{
		t: t,
		addrMap: map[string]string{
			"10.0.0.2": "www.google.com",
			"10.0.0.3": "www.baidu.com",
		},
	}

	table := NewTable(&sinffer{}, tp)

	for _, v := range []string{
		"10.0.0.2",
		"10.0.0.3",
		"www.x.com",
		"114.114.114.114",
	} {
		for range 10 {
			ctx := context.Background()
			ctx = netapi.WithContext(ctx)

			dstAddr, err := netapi.ParseAddressPort("tcp", v, 80)
			assert.NoError(t, err)
			err = table.Write(ctx, netapi.NewPacket(
				dstAddr,
				dstAddr,
				[]byte("test"),
				netapi.WriteBackFunc(func(b []byte, addr net.Addr) (int, error) {
					assert.Equal(t, addr.String(), net.JoinHostPort(v, "80"))
					return 0, nil
				}),
			))
			assert.NoError(t, err)
		}
	}

	time.Sleep(time.Second * 3)
}

type sinffer struct{}

func (sinffer) Packet(ctx *netapi.Context, pkt []byte) {}

type testProxy struct {
	t       *testing.T
	addrMap map[string]string
}

func (testProxy) Conn(context.Context, netapi.Address) (net.Conn, error) {
	return nil, errors.ErrUnsupported
}

func (t *testProxy) PacketConn(ctx context.Context, addr netapi.Address) (net.PacketConn, error) {
	var ip bool = true
	if addr.Hostname() == "www.google.com" || addr.Hostname() == "10.0.0.2" {
		ip = false
	}

	x, ok := t.addrMap[addr.Hostname()]
	if ok {
		store := netapi.GetContext(ctx)

		if x == "www.google.com" {
			store.ConnOptions().Resolver().SetSkipResolve(true)
			store.SetFakeIP(addr)
		}
	}

	t.t.Log("new packet conn", addr, ip)

	return &testPacketConn{saddr: netapi.EmptyAddr, t: t.t, ip: ip}, nil
}

func (t *testProxy) Ping(ctx context.Context, addr netapi.Address) (uint64, error) {
	return 0, nil
}

func (t *testProxy) Dispatch(ctx context.Context, addr netapi.Address) (netapi.Address, error) {
	if t.addrMap == nil {
		return addr, nil
	}

	x, ok := t.addrMap[addr.Hostname()]
	if !ok {
		return addr, nil
	}

	store := netapi.GetContext(ctx)

	var err error
	if x == "www.google.com" {
		store.ConnOptions().Resolver().SetSkipResolve(true)
		addr, err = netapi.ParseAddressPort(addr.Network(), x, addr.Port())
		if err != nil {
			return nil, err
		}
	}

	return netapi.ParseAddressPort(addr.Network(), x, addr.Port())
}

func (t *testProxy) Close() error { return nil }

type testPacketConn struct {
	t     *testing.T
	saddr netapi.Address
	read  bool
	write bool

	ip bool

	mu sync.Mutex
}

func (t *testPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	if t.read {
		return 0, nil, io.EOF
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	if t.read {
		return 0, nil, io.EOF
	}

	for !t.write {
		runtime.Gosched()
	}

	addr = t.saddr

	t.read = true
	if !t.saddr.IsFqdn() {
		addr = netapi.ParseIPAddr(t.saddr.Network(), t.saddr.(netapi.IPAddress).AddrPort().Addr().AsSlice(), 80)
	}

	t.t.Log(addr.String())

	return copy(p, []byte("test")), addr, nil
}

func (t *testPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	z, err := netapi.ParseSysAddr(addr)
	if err != nil {
		return 0, err
	}

	assert.Equal(t.t, t.ip, !z.IsFqdn(), addr)

	t.t.Log("write to remote", string(p), addr)
	t.saddr = z
	t.write = true
	return len(p), nil
}

func (t *testPacketConn) Close() error {
	return nil
}
func (t *testPacketConn) LocalAddr() net.Addr {
	return nil
}

func (t *testPacketConn) SetDeadline(time.Time) error {
	return nil
}

func (t *testPacketConn) SetReadDeadline(time.Time) error {
	return nil
}

func (t *testPacketConn) SetWriteDeadline(time.Time) error {
	return nil
}

func TestP(t *testing.T) {
	var natTable = map[string]net.PacketConn{}
	var getTargetAddress = func([]byte) (*net.UDPAddr, []byte) {
		// TODO implement proxy protocol
		return nil, nil
	}

	var packetResponse = func(net.Addr, []byte) []byte {
		// TODO implement proxy protocol
		return nil
	}

	pc, err := net.ListenPacket("udp", "")
	if err != nil {
		panic(err)
	}
	defer pc.Close()

	for {
		buf := make([]byte, 1024)
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			panic(err)
		}

		conn, ok := natTable[addr.String()]
		if !ok {
			conn, err = net.ListenPacket("udp", "")
			if err != nil {
				panic(err)
			}

			go func() {
				defer conn.Close()
				for {
					buf := make([]byte, 1024)
					n, src, err := conn.ReadFrom(buf)
					if err != nil {
						panic(err)
					}
					_, err = pc.WriteTo(packetResponse(src, buf[:n]), addr)
					if err != nil {
						panic(err)
					}
				}
			}()

			natTable[addr.String()] = conn
		}

		target, remain := getTargetAddress(buf[:n])

		_, err = conn.WriteTo(remain, target)
		if err != nil {
			panic(err)
		}
	}
}
