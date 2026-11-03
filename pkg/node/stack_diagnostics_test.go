package node

import (
	"testing"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/wireguard"
)

func TestTCPStackDiagnosticsThroughProtocolChain(t *testing.T) {
	vpn := func(mtu int32) contractnode.Protocol {
		return contractnode.Protocol{Type: "wireguard", Wireguard: &contractnode.Wireguard{Endpoint: []string{"192.0.2.1/32"}, MTU: mtu}}
	}
	wrap := contractnode.Protocol{Type: "bootstrap_dns_warp", BootstrapDNSWarp: &contractnode.BootstrapDNSWarp{}}
	split := func(tcp, udp *contractnode.Protocol) contractnode.Protocol {
		return contractnode.Protocol{Type: "network_split", NetworkSplit: &contractnode.NetworkSplit{TCP: tcp, UDP: udp}}
	}
	for _, test := range []struct {
		name  string
		chain []contractnode.Protocol
		mtu   int
	}{
		{"direct", []contractnode.Protocol{vpn(1300)}, 1300},
		{"wrapped", []contractnode.Protocol{vpn(1300), wrap}, 1300},
		{"split_tcp", []contractnode.Protocol{split(new(vpn(1300)), nil)}, 1300},
		{"split_udp_only", []contractnode.Protocol{split(nil, new(vpn(1400)))}, 0},
		{"split_udp_passthrough", []contractnode.Protocol{split(nil, new(vpn(1400))), {Type: "none", None: &contractnode.None{}}}, 0},
		{"split_both", []contractnode.Protocol{split(new(vpn(1300)), new(vpn(1400)))}, 1300},
		{"wrapped_split", []contractnode.Protocol{vpn(1300), wrap, split(new(wrap), nil)}, 1300},
		{"nested_carrier", []contractnode.Protocol{vpn(1400), vpn(1300)}, 1300},
	} {
		t.Run(test.name, func(t *testing.T) {
			runtime := newTestRuntime(t)
			n := contractnode.Node{ID: "vpn", Name: "vpn", Origin: "manual", Enabled: true, Chain: test.chain}
			if _, err := runtime.Save(t.Context(), n); err != nil {
				t.Fatal(err)
			}
			if got := runtime.ActiveTCPStackSnapshots(32); len(got) != 0 {
				t.Fatalf("diagnostics instantiated an inactive VPN: %+v", got)
			}
			if _, err := runtime.GetDialerByID(t.Context(), n.ID); err != nil {
				t.Fatal(err)
			}
			got := runtime.ActiveTCPStackSnapshots(32)
			if test.mtu == 0 {
				if len(got) != 0 {
					t.Fatalf("UDP-only stack reported as TCP: %+v", got)
				}
			} else if len(got) != 1 || got[0].NodeID != n.ID || got[0].Snapshot.MTU != test.mtu {
				t.Fatalf("running VPN stack missing from diagnostics: %+v", got)
			}
			runtime.proxies.Delete(n.ID)
			if got := runtime.ActiveTCPStackSnapshots(32); len(got) != 0 {
				t.Fatalf("diagnostics retained a closed VPN: %+v", got)
			}
		})
	}
}
