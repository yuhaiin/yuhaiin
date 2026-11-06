package dialer

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netstate"
)

type bindingRawConn struct{}

func (bindingRawConn) Control(f func(uintptr)) error  { f(10); return nil }
func (bindingRawConn) Read(func(uintptr) bool) error  { return nil }
func (bindingRawConn) Write(func(uintptr) bool) error { return nil }

func TestNativeBindingUsesActualNetworkInsteadOfSelection(t *testing.T) {
	m := netstate.NewManager()
	address := netip.MustParseAddr("127.0.0.1")
	a := netstate.Network{ID: "android:1", Name: "wifi", Index: 2, Available: true, Addresses: []netip.Addr{address}}
	b := netstate.Network{ID: "android:2", Name: "cell", Index: 3, Available: true, Addresses: []netip.Addr{address}}
	m.Apply(netstate.Snapshot{Networks: []netstate.Network{a, b}, Selected: a.ID}, false)
	ctx, cancel := context.WithCancelCause(t.Context())
	scope := &nativeBinding{manager: m, ctx: ctx, cancel: cancel, family: 4, bind: func(int32, string) (string, error) { return b.ID, nil }}
	defer scope.close()
	opts := &Options{}
	if err := scope.control(bindingRawConn{}, opts); err != nil {
		t.Fatal(err)
	}
	if !scope.path.Known() || opts.networkID != b.ID {
		t.Fatal("actual native binding was discarded")
	}
	raw, peer := tcpPair(t)
	c, err := trackTCP(m, raw, scope.path, opts.networkID)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	workerCtx, stop := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { defer close(done); m.Run(workerCtx) }()
	defer func() { stop(); <-done }()
	a.Available = false
	m.Apply(netstate.Snapshot{Networks: []netstate.Network{a, b}, Selected: b.ID}, false)
	if ctx.Err() != nil || !m.Valid(c.path) {
		t.Fatal("selected-network change canceled a socket actually bound elsewhere")
	}
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := peer.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Read(make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	b.Available = false
	m.Apply(netstate.Snapshot{Networks: []netstate.Network{a, b}}, false)
	select {
	case <-ctx.Done():
		if !errors.Is(context.Cause(ctx), netstate.ErrInvalidated) {
			t.Fatal(context.Cause(ctx))
		}
	case <-time.After(time.Second):
		t.Fatal("actual old-network dial was not canceled")
	}
}

func TestUnobservedNativeNetworkDoesNotBorrowAnotherNetworksAddress(t *testing.T) {
	m, s := socketManager(t)
	m.Apply(s, false)
	ctx, cancel := context.WithCancelCause(t.Context())
	scope := &nativeBinding{manager: m, ctx: ctx, cancel: cancel, family: 4, bind: func(int32, string) (string, error) { return "android:new", nil }}
	defer scope.close()
	opts := &Options{}
	if err := scope.control(bindingRawConn{}, opts); err != nil {
		t.Fatal(err)
	}
	raw, _ := tcpPair(t)
	c, err := trackTCP(m, raw, scope.path, opts.networkID)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if scope.path.Known() || c.path.Known() {
		t.Fatal("new Network borrowed an obsolete Network's identical local address")
	}
	m.InterfaceUnavailable(1)
	if ctx.Err() != nil || !m.Valid(c.path) {
		t.Fatal("unknown actual binding caused speculative cleanup")
	}
}
