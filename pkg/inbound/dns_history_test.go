package inbound

import (
	"context"
	"errors"
	"net"
	"testing"

	"codeberg.org/miekg/dns"
	contract "github.com/Asutorufa/yuhaiin/pkg/contract/access"
	"github.com/Asutorufa/yuhaiin/pkg/net/accesscontrol"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxyauth"
	"github.com/Asutorufa/yuhaiin/pkg/pool"
)

type inboundHistory struct{ records []*netapi.DNSTraceData }

func (h *inboundHistory) BeginDNS(transport, source string) *netapi.DNSTrace {
	return netapi.NewDNSTrace(transport, source, func(d *netapi.DNSTraceData) { h.records = append(h.records, d) })
}

func hijackQuery(t *testing.T) []byte {
	q := netapi.NewDNSMsg(netapi.DNSQuestion{Name: "secret.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET})
	q.Response = false
	if err := q.Pack(); err != nil {
		t.Fatal(err)
	}
	return q.Data
}

// Requests rejected before the DNS agent still get one history record with
// the client, inbound and question, and the reason for the rejection.
func TestDNSHistoryRecordsInboundRejections(t *testing.T) {
	access := accesscontrol.New()
	defer access.Close()
	prepare := func(action string) {
		p, err := accesscontrol.Prepare(contract.Config{Enabled: true, Scope: contract.Scope{AllInbounds: true}, DefaultAction: action})
		if err != nil {
			t.Fatal(err)
		}
		access.Activate(p)
	}
	history := new(inboundHistory)
	agent := new(usageDNSAgent)
	inbound := NewInbound(netapi.NewErrProxy(errors.New("unexpected forwarding")), WithDNSAgent(agent), WithTrafficAccess(access), WithDNSObserver(history))
	defer inbound.Close()
	identity := &proxyauth.Identity{UserID: "alice", CredentialID: "phone", GroupIDs: []string{"family"}, Context: t.Context()}
	packet := func(id *proxyauth.Identity) *netapi.Packet {
		p := netapi.NewPacket(&net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 1234}, netapi.ParseIPAddr("udp", net.IPv4(192, 0, 2, 53), 53), pool.Clone(hijackQuery(t)),
			netapi.WriteBackFunc(func(b []byte, _ net.Addr) (int, error) { return len(b), nil }), netapi.WithDNSRequest(true), netapi.WithInboundID("entry"))
		p.Identity = id
		return p
	}

	prepare("deny")
	inbound.handlePacket(packet(identity))
	if agent.request != nil || len(history.records) != 1 {
		t.Fatalf("denied request: agent=%v records=%d", agent.request, len(history.records))
	}
	d := history.records[0]
	if d.Outcome != netapi.DNSOutcomeRejected || d.FailureStage != netapi.DNSStageAuthorization || d.FailureReason != "traffic_access_denied" {
		t.Fatalf("denied = %+v", d)
	}
	if d.SourceType != netapi.DNSSourceHijack || d.ClientIP != "192.0.2.1" || d.InboundID != "entry" || d.UserID != "alice" || d.Domain != "secret.example." || len(d.GroupIDs) != 1 {
		t.Fatalf("denied context = %+v", d)
	}

	expired, cancel := context.WithCancel(t.Context())
	cancel()
	inbound.handlePacket(packet(&proxyauth.Identity{UserID: "bob", Context: expired}))
	if len(history.records) != 2 || history.records[1].FailureReason != "identity_invalid" || history.records[1].UserID != "bob" {
		t.Fatalf("invalid identity = %+v", history.records[len(history.records)-1])
	}

	// An admitted request hands its trace to the DNS agent, which owns it.
	prepare("allow")
	inbound.handlePacket(packet(identity))
	if agent.request == nil || agent.request.Trace == nil || len(history.records) != 2 {
		t.Fatal("admitted request did not carry its trace")
	}
	prepare("deny")
	if err := agent.request.WriteBack([]byte("answer")); err == nil {
		t.Fatal("revoked reply was written")
	}
	agent.request.Trace.Finish(errors.New("revoked"))
	agent.request.Done(nil)
	agent.request.Question.DecRef()
	if d := history.records[2]; (d.FailureReason != "traffic_access_revoked" && d.FailureReason != "authorization_ended") || d.Outcome != netapi.DNSOutcomeRejected || d.FailureStage != netapi.DNSStageAuthorization {
		t.Fatalf("revoked = %+v", d)
	}
}

func TestDNSHistoryDisabledObserverStartsNoTrace(t *testing.T) {
	agent := new(usageDNSAgent)
	inbound := NewInbound(netapi.NewErrProxy(errors.New("unexpected forwarding")), WithDNSAgent(agent))
	defer inbound.Close()
	p := netapi.NewPacket(&net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 1234}, netapi.ParseIPAddr("udp", net.IPv4(192, 0, 2, 53), 53), pool.Clone(hijackQuery(t)),
		netapi.WriteBackFunc(func(b []byte, _ net.Addr) (int, error) { return len(b), nil }), netapi.WithDNSRequest(true))
	inbound.handlePacket(p)
	if agent.request == nil || agent.request.Trace != nil {
		t.Fatal("disabled history attached a trace")
	}
	agent.request.Done(nil)
	agent.request.Question.DecRef()
}
