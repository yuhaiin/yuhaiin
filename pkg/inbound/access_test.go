package inbound

import (
	"errors"
	"net"
	"testing"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/access"
	"github.com/Asutorufa/yuhaiin/pkg/net/accesscontrol"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxyauth"
	"github.com/Asutorufa/yuhaiin/pkg/pool"
)

func TestAccessPolicyProtectsLocalDNSAndRevokesPendingReply(t *testing.T) {
	access := accesscontrol.New()
	defer access.Close()
	prepare := func(action string) {
		t.Helper()
		p, err := accesscontrol.Prepare(contract.Config{Enabled: true, Scope: contract.Scope{AllInbounds: true}, DefaultAction: action})
		if err != nil {
			t.Fatal(err)
		}
		access.Activate(p)
	}
	prepare("deny")
	agent := new(usageDNSAgent)
	inbound := NewInbound(netapi.NewErrProxy(errors.New("unexpected forwarding")), WithDNSAgent(agent), WithTrafficAccess(access))
	defer inbound.Close()
	identity := &proxyauth.Identity{UserID: "alice", CredentialID: "phone", Context: t.Context()}
	packet := func(authenticated bool) *netapi.Packet {
		p := netapi.NewPacket(&net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 1234}, netapi.ParseIPAddr("udp", net.IPv4(192, 0, 2, 53), 53), pool.Clone([]byte("query")), netapi.WriteBackFunc(func(b []byte, _ net.Addr) (int, error) { t.Error("revoked DNS response escaped"); return len(b), nil }), netapi.WithDNSRequest(true), netapi.WithInboundID("entry"))
		if authenticated {
			p.Identity = identity
		}
		return p
	}
	inbound.handlePacket(packet(true))
	if agent.request != nil {
		t.Fatal("default deny reached local resolver")
	}
	prepare("allow")
	inbound.handlePacket(packet(false))
	if agent.request != nil {
		t.Fatal("anonymous DNS reached managed resolver")
	}
	inbound.handlePacket(packet(true))
	if agent.request == nil {
		t.Fatal("authenticated allowed DNS not handled")
	}
	if access.Status().Sessions != 1 {
		t.Fatal("pending DNS not tracked")
	}
	prepare("deny")
	if err := agent.request.WriteBack([]byte("answer")); err == nil {
		t.Fatal("pending DNS reply survived revocation")
	}
	agent.request.Done(nil)
	agent.request.Question.DecRef()
	if access.Status().Sessions != 0 {
		t.Fatal("DNS session leaked")
	}
}
