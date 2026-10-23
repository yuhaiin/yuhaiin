package nat

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/access"
	rule "github.com/Asutorufa/yuhaiin/pkg/contract/route"
	"github.com/Asutorufa/yuhaiin/pkg/net/accesscontrol"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxyauth"
)

func natPolicy(t *testing.T, c *accesscontrol.Controller, allow bool) {
	t.Helper()
	cfg := contract.Config{Enabled: true, Scope: contract.Scope{AllInbounds: true}, DefaultAction: "deny"}
	if allow {
		cfg.Rules = []contract.Rule{{ID: "allow", Action: "allow", Conditions: []rule.RuleExpr{{Type: "destination", Destination: &rule.DestinationExpr{Domains: []string{"service.example"}, CIDRs: []string{"192.0.2.0/24"}}}}}}
	}
	p, err := accesscontrol.Prepare(cfg)
	if err != nil {
		t.Fatal(err)
	}
	c.Activate(p)
}

type accessPacketConn struct {
	net.PacketConn
	writes atomic.Int32
}

func (*accessPacketConn) SetReadDeadline(time.Time) error { return nil }

func (c *accessPacketConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	c.writes.Add(1)
	return len(b), nil
}

func TestAccessRechecksCachedSendAndRewrittenReply(t *testing.T) {
	controller := accesscontrol.New()
	defer controller.Close()
	natPolicy(t, controller, true)
	identity := &proxyauth.Identity{UserID: "alice", CredentialID: "phone", Context: t.Context()}
	var cancelled atomic.Bool
	session, err := controller.NewSession(netapi.TrafficSubject{External: true, InboundID: "entry", Identity: identity}, func(error) { cancelled.Store(true) })
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	u := &SourceControl{access: session}
	conn := new(accessPacketConn)
	original, _ := netapi.ParseAddress("udp", "service.example:443")
	real := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 8), Port: 443}
	if err := u.writeAuthorizedPacket(nil, []byte("payload"), real, original, conn); err != nil {
		t.Fatal(err)
	}
	if conn.writes.Load() != 1 {
		t.Fatal("allowed packet not sent")
	}
	natPolicy(t, controller, false)
	if !cancelled.Load() {
		t.Fatal("retained datagram authorization not revoked")
	}
	if err := u.writeAuthorizedPacket(nil, []byte("payload"), real, original, conn); !errors.Is(err, netapi.ErrTrafficAccessDenied) {
		t.Fatal("cached target bypass", err)
	}
	if err := u.writeReply(context.Background(), []byte("reply"), original, real); !errors.Is(err, netapi.ErrTrafficAccessDenied) {
		t.Fatal("domain-rewritten queued reply bypass", err)
	}
	if conn.writes.Load() != 1 {
		t.Fatal("denied datagram reached socket")
	}
}

func TestAccessManagedNATRejectsAnonymousBeforeSocketCreation(t *testing.T) {
	controller := accesscontrol.New()
	defer controller.Close()
	natPolicy(t, controller, true)
	var dials atomic.Int32
	table := NewTable(nil, lifecycleDialer{dial: func(context.Context) (net.PacketConn, error) {
		dials.Add(1)
		return nil, errors.New("unexpected socket")
	}})
	table.SetTrafficAccess(controller)
	defer table.Close()
	pkt := lifecyclePacket()
	defer pkt.DecRef()
	netapi.WithInboundID("entry")(pkt)
	if err := table.Write(t.Context(), pkt); !errors.Is(err, netapi.ErrTrafficAccessDenied) {
		t.Fatal("anonymous admission", err)
	}
	if dials.Load() != 0 || table.ResourceStats().Sessions != 0 {
		t.Fatal("rejected admission retained socket or resource", table.ResourceStats())
	}
}
