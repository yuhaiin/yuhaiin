package inbound

import (
	"net/netip"
	"testing"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

func TestUserAuthenticationRequiresInstalledProvider(t *testing.T) {
	config := contract.Inbound{ID: "entry", Enabled: true, Authentication: &contract.Authentication{Users: []string{"alice"}}, Network: contract.NewTypedNetwork(contract.TCPUDPNetwork{Host: "127.0.0.1:0", UDP: contract.UDPTCPOnly}), Protocol: contract.NewTypedProtocol(contract.HTTPProtocol{})}
	if server, err := listenContract(config, netapi.NewChannelHandler(t.Context()), [2]netip.Prefix{}); err == nil {
		_ = server.Close()
		t.Fatal("missing identity module admitted user authentication")
	}
	config.Authentication = nil
	server, err := listenContract(config, netapi.NewChannelHandler(t.Context()), [2]netip.Prefix{})
	if err != nil {
		t.Fatalf("legacy listener requires identity module: %v", err)
	}
	_ = server.Close()
}
