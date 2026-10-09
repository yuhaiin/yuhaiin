package hysteria2

import (
	"context"
	"errors"
	"net"
	"reflect"
	"sync/atomic"
	"testing"

	node "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

type addressHopTestResolver struct {
	netapi.Resolver
	lookup func(context.Context, string) (*netapi.IPs, error)
}

func (r *addressHopTestResolver) LookupIP(ctx context.Context, name string, _ ...func(*netapi.LookupIPOption)) (*netapi.IPs, error) {
	return r.lookup(ctx, name)
}

func TestAddressHopDNSExpandsAndMergesAllAnswers(t *testing.T) {
	var primaryCalls, secondaryCalls atomic.Int32
	ctx := netapi.WithContext(t.Context())
	ctx.ConnOptions().Resolver().SetResolver(&addressHopTestResolver{lookup: func(_ context.Context, name string) (*netapi.IPs, error) {
		switch name {
		case "relays.example":
			primaryCalls.Add(1)
			return &netapi.IPs{A: []net.IP{net.ParseIP("127.0.0.2"), net.ParseIP("127.0.0.3"), net.ParseIP("127.0.0.2")}, AAAA: []net.IP{net.ParseIP("::1")}}, nil
		case "other.example":
			secondaryCalls.Add(1)
			return &netapi.IPs{A: []net.IP{net.ParseIP("127.0.0.3"), net.ParseIP("127.0.0.4")}}, nil
		default:
			return nil, errors.New("unexpected DNS lookup")
		}
	}})
	addr, err := resolveAddressHops(ctx, node.Hysteria2{
		Host:         "relays.example:443,20000-20001",
		HopAddresses: []string{"RELAYS.EXAMPLE.:20001-20002", "other.example", "[::1]:8443", "127.0.0.4:443"},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := make(map[string][]uint16)
	for _, target := range addr.targets {
		got[target.ip.String()] = target.ports
	}
	want := map[string][]uint16{
		"127.0.0.2": {443, 20000, 20001, 20002},
		"127.0.0.3": {443, 20000, 20001, 20002},
		"127.0.0.4": {443},
		"::1":       {443, 8443, 20000, 20001, 20002},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("DNS hop targets = %v, want %v", got, want)
	}
	if primaryCalls.Load() != 1 || secondaryCalls.Load() != 1 {
		t.Fatalf("repeated DNS lookup: primary %d, secondary %d", primaryCalls.Load(), secondaryCalls.Load())
	}
}

func TestAddressHopDNSFailures(t *testing.T) {
	for _, tc := range []struct {
		name string
		ips  *netapi.IPs
		err  error
	}{
		{name: "empty answer", ips: &netapi.IPs{}},
		{name: "lookup failure", err: errors.New("DNS unavailable")},
		{name: "cancelled", err: context.Canceled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := netapi.WithContext(t.Context())
			ctx.ConnOptions().Resolver().SetResolver(&addressHopTestResolver{lookup: func(context.Context, string) (*netapi.IPs, error) {
				return tc.ips, tc.err
			}})
			_, err := resolveAddressHops(ctx, node.Hysteria2{Host: "127.0.0.2:443", HopAddresses: []string{"relays.example:443"}})
			if err == nil || (tc.err != nil && !errors.Is(err, tc.err)) {
				t.Fatalf("resolve error = %v", err)
			}
		})
	}
}

func TestOrdinaryHostnameStillSelectsOneAddress(t *testing.T) {
	ctx := netapi.WithContext(t.Context())
	ctx.ConnOptions().Resolver().SetResolver(&addressHopTestResolver{lookup: func(context.Context, string) (*netapi.IPs, error) {
		return &netapi.IPs{A: []net.IP{net.ParseIP("127.0.0.2"), net.ParseIP("127.0.0.3")}, AAAA: []net.IP{net.ParseIP("::1")}}, nil
	}})
	server, _, err := parseServerAddress("relays.example:8443")
	if err != nil {
		t.Fatal(err)
	}
	remote, err := resolveHopAddress(ctx, server)
	if err != nil || remote.Port != 8443 {
		t.Fatalf("ordinary endpoint = %v: %v", remote, err)
	}
	if ip := remote.IP.String(); ip != "127.0.0.2" && ip != "127.0.0.3" && ip != "::1" {
		t.Fatalf("ordinary endpoint selected an unknown IP: %v", remote)
	}
}

func TestHysteriaSocketAddressFamily(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "::1"} {
		t.Run(ip, func(t *testing.T) {
			remote := &net.UDPAddr{IP: net.ParseIP(ip), Port: 443}
			conn, err := (&connFactory{}).listenPacket(t.Context(), remote)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			local := conn.LocalAddr().(*net.UDPAddr)
			if (local.IP.To4() != nil) != (remote.IP.To4() != nil) {
				t.Fatalf("socket family %v doesn't match target %v", local, remote)
			}
		})
	}
}
