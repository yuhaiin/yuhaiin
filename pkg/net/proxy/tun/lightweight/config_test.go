package lightweight

import (
	"context"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/trafficcontrol"
)

func TestOutputSchedulerDefaultAndOptIn(t *testing.T) {
	for _, mode := range []trafficcontrol.SchedulerMode{"", trafficcontrol.SchedulerFIFO, trafficcontrol.SchedulerFair} {
		for _, profile := range []NetworkProfile{LocalTun, RemoteTunnel} {
			cfg, err := (Config{OutputScheduler: mode, Profile: profile}).normalize()
			if err != nil {
				t.Fatal(err)
			}
			want := mode
			if want == "" {
				want = trafficcontrol.SchedulerFIFO
			}
			if cfg.OutputScheduler != want {
				t.Fatalf("profile=%v scheduler=%q, want %q", profile, cfg.OutputScheduler, want)
			}
		}
	}
}

func TestProfileCongestionDefault(t *testing.T) {
	for _, tc := range []struct {
		name      string
		cfg       Config
		algorithm string
	}{
		{name: "local", algorithm: "cubic"},
		{name: "remote", cfg: Config{Profile: RemoteTunnel}, algorithm: "bbr"},
		{name: "explicit-remote", cfg: Config{Profile: RemoteTunnel, CongestionControl: "reno"}, algorithm: "reno"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, server := stackPairConfig(t, tc.cfg)
			remote := netip.MustParseAddrPort("192.0.2.2:8080")
			listener, err := server.ListenTCP(remote)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			conn, err := client.DialContextTCP(ctx, remote)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			peer, err := listener.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer peer.Close()
			// Verify both active and passive connections constructed the chosen
			// controller, rather than checking only the normalized config string.
			for _, c := range []*TCPConn{conn.(*TCPConn), peer.(*TCPConn)} {
				c.mu.Lock()
				kind := reflect.TypeOf(c.controller).Elem().Name()
				c.mu.Unlock()
				if kind != tc.algorithm {
					t.Fatalf("controller=%s, want %s", kind, tc.algorithm)
				}
			}
		})
	}
}
func TestAddressFamilyMTU(t *testing.T) {
	if err := ValidateConfig(Config{MTU: 575}); err == nil {
		t.Fatal("local TUN accepted MTU below 576")
	}

	for _, tc := range []struct {
		name      string
		mtu       int
		addresses []netip.Addr
		invalid   bool
	}{
		{name: "IPv4-minimum", mtu: 576, addresses: []netip.Addr{netip.MustParseAddr("192.0.2.1")}},
		{name: "IPv4-too-small", mtu: 575, invalid: true},
		{name: "IPv6-minimum", mtu: 1280, addresses: []netip.Addr{netip.MustParseAddr("2001:db8::1")}},
		{name: "IPv6-too-small", mtu: 1279, addresses: []netip.Addr{netip.MustParseAddr("2001:db8::1")}, invalid: true},
		{name: "dual-too-small", mtu: 1000, addresses: []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")}, invalid: true},
	} {
		for _, profile := range []NetworkProfile{LocalTun, RemoteTunnel} {
			t.Run(string(profile)+"/"+tc.name, func(t *testing.T) {
				err := ValidateConfig(Config{MTU: tc.mtu, Addresses: tc.addresses, Profile: profile})
				if (err != nil) != tc.invalid {
					t.Fatalf("unexpected config result: %v", err)
				}
			})
		}
	}
}

func TestLocalIPv4SmallMTU(t *testing.T) {
	if err := ValidateConfig(Config{Profile: LocalTun, MTU: 1200, Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.1")}}); err != nil {
		t.Fatal(err)
	}
}
