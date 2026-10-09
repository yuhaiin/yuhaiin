package hysteria2

import (
	"testing"

	node "github.com/Asutorufa/yuhaiin/pkg/contract/node"
)

func TestPortHoppingConfig(t *testing.T) {
	for _, tc := range []struct {
		name   string
		config node.Hysteria2
		valid  bool
	}{
		{"single port unchanged", node.Hysteria2{Host: "example.com:443"}, true},
		{"default port unchanged", node.Hysteria2{Host: "example.com"}, true},
		{"list and range", node.Hysteria2{Host: "example.com:443,20000-50000"}, true},
		{"relay list", node.Hysteria2{Host: "relay-a.example:443", HopAddresses: []string{"relay-b.example:20000-20020", "[::1]:443,8443"}}, true},
		{"relay default port", node.Hysteria2{Host: "relay-a.example", HopAddresses: []string{"relay-b.example"}}, true},
		{"empty relay", node.Hysteria2{Host: "example.com:443", HopAddresses: []string{""}}, false},
		{"missing relay host", node.Hysteria2{Host: "example.com:443", HopAddresses: []string{":443"}}, false},
		{"invalid relay ports", node.Hysteria2{Host: "example.com:443", HopAddresses: []string{"relay.example:0,443"}}, false},
		{"scoped relay", node.Hysteria2{Host: "example.com:443", HopAddresses: []string{"[fe80::1%eth0]:443"}}, false},
		{"IPv6 range", node.Hysteria2{Host: "[::1]:20000-20002", HopIntervalSeconds: 5}, true},
		{"random interval", node.Hysteria2{Host: "example.com:20000-20002", MinHopIntervalSeconds: 5, MaxHopIntervalSeconds: 30}, true},
		{"zero port", node.Hysteria2{Host: "example.com:0,443"}, false},
		{"out of range", node.Hysteria2{Host: "example.com:443,65536"}, false},
		{"empty element", node.Hysteria2{Host: "example.com:443,"}, false},
		{"too short", node.Hysteria2{Host: "example.com:20000-20002", HopIntervalSeconds: 4}, false},
		{"mixed intervals", node.Hysteria2{Host: "example.com:20000-20002", HopIntervalSeconds: 30, MinHopIntervalSeconds: 5, MaxHopIntervalSeconds: 10}, false},
		{"missing maximum", node.Hysteria2{Host: "example.com:20000-20002", MinHopIntervalSeconds: 5}, false},
		{"missing minimum", node.Hysteria2{Host: "example.com:20000-20002", MaxHopIntervalSeconds: 10}, false},
		{"reversed interval", node.Hysteria2{Host: "example.com:20000-20002", MinHopIntervalSeconds: 10, MaxHopIntervalSeconds: 5}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.config.Auth = "secret"
			client, err := NewClient(tc.config, nil)
			if (err == nil) != tc.valid {
				t.Fatalf("NewClient error = %v, valid = %v", err, tc.valid)
			}
			if client != nil {
				_ = client.Close()
			}
		})
	}
}
