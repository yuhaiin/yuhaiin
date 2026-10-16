package dialer

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

func TestHappyEyeballsDirectDialReturnsTrueNilOnFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	addr := netapi.ParseNetipAddr("tcp", netip.MustParseAddr("192.0.2.1"), 443)
	for _, tt := range []struct {
		name string
		dial func(context.Context, netapi.Address) (net.Conn, error)
	}{
		{name: "v2", dial: DialHappyEyeballsv2},
		{name: "v1", dial: DialHappyEyeballsv1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			conn, err := tt.dial(ctx, addr)
			if err == nil {
				t.Fatal("canceled dial succeeded")
			}
			// This used to be a non-nil net.Conn holding (*net.TCPConn)(nil).
			if conn != nil {
				t.Fatalf("failed dial returned typed-nil interface %T", conn)
			}
		})
	}
}

func TestHappyEyeballsV2GenericRejectsNilSuccess(t *testing.T) {
	addr := netapi.ParseNetipAddr("tcp", netip.MustParseAddr("192.0.2.1"), 443)
	d := NewHappyEyeballsv2Dialer(func(context.Context, net.IP, uint16) (*net.TCPConn, error) {
		return nil, nil
	})
	conn, err := d.DialHappyEyeballsv2(t.Context(), addr)
	if conn != nil || err == nil {
		t.Fatalf("nil success = (%v, %v), want failure", conn, err)
	}

	want := errors.New("dial failed")
	d = NewHappyEyeballsv2Dialer(func(context.Context, net.IP, uint16) (*net.TCPConn, error) {
		return nil, want
	})
	conn, err = d.DialHappyEyeballsv2(t.Context(), addr)
	if conn != nil || !errors.Is(err, want) {
		t.Fatalf("typed-nil failure = (%v, %v), want %v", conn, err, want)
	}
}

func TestHappyEyeballsParallelDoesNotReturnTypedNil(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	addr := netip.MustParseAddrPort("192.0.2.1:443")
	for _, fallback := range [][]netip.AddrPort{nil, {netip.MustParseAddrPort("[2001:db8::1]:443")}} {
		conn, err := DialParallel(ctx, []netip.AddrPort{addr}, fallback)
		if err == nil || conn != nil {
			t.Fatalf("canceled parallel dial = (%v, %v)", conn, err)
		}
	}
}
