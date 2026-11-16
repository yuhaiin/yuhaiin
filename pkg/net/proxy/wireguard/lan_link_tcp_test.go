package wireguard

import (
	"testing"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	"github.com/Asutorufa/yuhaiin/pkg/contract/transport"
)

func TestLANLinkGatewayTCPSettings(t *testing.T) {
	cfg := contract.LANLinkGateway{Networks: []string{"192.168.50.0/24"}}
	if err := cfg.FillDefaults(); err != nil {
		t.Fatal(err)
	}
	client, err := cfg.AddClient(1, "")
	if err != nil {
		t.Fatal(err)
	}
	base := linkSpec(cfg, client)
	cfg.TCPSettings = &transport.TCPSettings{CongestionControl: "cubic", LossRecovery: "rack-tlp"}
	if err := validateGateway(cfg); err != nil {
		t.Fatal(err)
	}
	if linkSpec(cfg, client) == base {
		t.Fatal("changing TCP settings must restart the client link")
	}
	cfg.TCPSettings = &transport.TCPSettings{CongestionControl: "vegas"}
	if err := validateGateway(cfg); err == nil {
		t.Fatal("unknown congestion control accepted")
	}
}
