package node

import (
	"encoding/json/v2"
	"fmt"
	"testing"
)

func TestVPNSharedTCPSettings(t *testing.T) {
	for _, kind := range []string{"wireguard", "amneziawg", "openvpn", "l2tp", "l2tpv3", "globalprotect", "softether", "ikev2", "anyconnect", "sstp", "fortinet", "nebula", "zerotier", "tailscale", "masque", "cloudflare_warp_masque"} {
		t.Run(kind, func(t *testing.T) {
			var p Protocol
			raw := fmt.Sprintf(`{"type":%q,%q:{"tcpSettings":{"congestionControl":"cubic","lossRecovery":"rack-tlp"}}}`, kind, kind)
			if err := json.Unmarshal([]byte(raw), &p); err != nil {
				t.Fatal(err)
			}
			if err := p.Validate(); err != nil {
				t.Fatal(err)
			}
			settings := p.TCPOptions()
			if settings == nil || settings.CongestionControl != "cubic" || settings.LossRecovery != "rack-tlp" {
				t.Fatalf("missing shared settings: %+v", settings)
			}
			data, err := json.Marshal(p)
			if err != nil {
				t.Fatal(err)
			}
			var roundtrip Protocol
			if err := json.Unmarshal(data, &roundtrip); err != nil {
				t.Fatal(err)
			}
			if *roundtrip.TCPOptions() != *settings {
				t.Fatal("TCP settings lost in persistence")
			}
		})
	}
}
