package resolver

import (
	"errors"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

func TestFakeIPUnmappedNeverFallsThrough(t *testing.T) {
	f := newFakeDNSForRoutes(t)
	addr, err := netapi.ParseAddress("tcp", "198.18.0.9:443")
	if err != nil {
		t.Fatal(err)
	}
	ctx := netapi.WithContext(t.Context())
	ctx.ConnOptions().SetRouteMode("direct")
	if got := f.dispatchAddr(ctx, addr); got != addr {
		t.Fatalf("unmapped destination changed: %v", got)
	}
	if !ctx.ConnOptions().UnmappedFakeIP() {
		t.Fatal("unmapped destination did not get an unconditional route-block marker")
	}
	for name, invoke := range map[string]func() error{
		"Conn": func() error {
			_, err := f.Conn(ctx, addr)
			return err
		},
		"PacketConn": func() error {
			_, err := f.PacketConn(ctx, addr)
			return err
		},
		"Dispatch": func() error {
			_, err := f.Dispatch(ctx, addr)
			return err
		},
		"Ping": func() error {
			_, err := f.Ping(ctx, addr)
			return err
		},
	} {
		if err := invoke(); !errors.Is(err, ErrUnmappedFakeIP) {
			t.Errorf("%s did not fail closed: %v", name, err)
		}
	}
}

func TestFakeIPValidAddressRecoversDomain(t *testing.T) {
	f := newFakeDNSForRoutes(t)
	ips, err := f.fake.LookupIP(t.Context(), "example.com", func(o *netapi.LookupIPOption) { o.Mode = netapi.ResolverModePreferIPv4 })
	if err != nil || len(ips.A) != 1 {
		t.Fatalf("failed to allocate fakeip: %v %v", ips, err)
	}
	addr, err := netapi.ParseAddress("tcp", ips.A[0].String()+":443")
	if err != nil {
		t.Fatal(err)
	}
	ctx := netapi.WithContext(t.Context())
	if got := f.dispatchAddr(ctx, addr); !got.IsFqdn() || got.Hostname() != "example.com" {
		t.Fatalf("could not restore mapped domain: %v", got)
	}
	if ctx.ConnOptions().UnmappedFakeIP() {
		t.Fatal("valid mapping was marked unsafe")
	}
}
