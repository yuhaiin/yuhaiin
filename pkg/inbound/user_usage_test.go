package inbound

import (
	"context"
	"errors"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"

	usage "github.com/Asutorufa/yuhaiin/pkg/contract/usage"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxyauth"
	"github.com/Asutorufa/yuhaiin/pkg/pool"
	"github.com/Asutorufa/yuhaiin/pkg/statistics"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
)

type usageDNSAgent struct{ request *netapi.DNSRawRequest }

func (a *usageDNSAgent) DoDatagram(_ context.Context, r *netapi.DNSRawRequest) error {
	r.Question.IncRef()
	a.request = r
	return nil
}
func (*usageDNSAgent) DoStream(_ context.Context, r *netapi.DNSStreamRequest) error {
	if _, err := io.ReadFull(r.Conn, make([]byte, 5)); err != nil {
		return err
	}
	_, err := r.Conn.Write([]byte("answer"))
	return err
}
func (*usageDNSAgent) Close() error     { return nil }
func (*usageDNSAgent) SetServer(string) {}

func TestUserUsageLocalDNSWaitsForAsynchronousCompletion(t *testing.T) {
	db, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	recorder, err := statistics.NewUserUsage(db.DB(), statistics.DefaultUsageOptions())
	if err != nil {
		t.Fatal(err)
	}
	defer recorder.Close()
	agent := new(usageDNSAgent)
	runtime := NewInbound(netapi.NewErrProxy(errors.New("unexpected outbound")), WithUserUsage(recorder), WithDNSAgent(agent))
	defer runtime.Close()
	target := netapi.ParseIPAddr("udp", net.IPv4(192, 0, 2, 53), 53)
	pkt := netapi.NewPacket(&net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 1234}, target, pool.Clone([]byte("query")), netapi.WriteBackFunc(func(p []byte, _ net.Addr) (int, error) { return len(p), nil }), netapi.WithDNSRequest(true), netapi.WithInboundID("entry"))
	pkt.Identity = &proxyauth.Identity{UserID: "alice", CredentialID: "phone", Context: t.Context()}
	runtime.handlePacket(pkt)
	first, err := recorder.Report(t.Context(), usage.Query{UserID: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if first.Summary.ActiveUDP != 1 {
		t.Fatalf("closed before asynchronous completion: %+v", first.Summary)
	}
	// Make the response arrive after the recorder's first sampling interval.
	select {
	case <-time.After(1100 * time.Millisecond):
	case <-t.Context().Done():
		t.Fatal(t.Context().Err())
	}
	if err := agent.request.WriteBack([]byte("answer")); err != nil {
		t.Fatal(err)
	}
	agent.request.Done(nil)
	agent.request.Question.DecRef()
	deadline := time.Now().Add(3 * time.Second)
	for {
		report, err := recorder.Report(t.Context(), usage.Query{UserID: "alice"})
		if err != nil {
			t.Fatal(err)
		}
		if report.Summary.Lifetime.Download == "6" {
			if report.Summary.Lifetime.Upload != "5" || report.Summary.ActiveUDP != 0 || len(report.Nodes) != 1 || report.Nodes[0].ID != "@local-dns" {
				t.Fatalf("DNS usage=%+v", report)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("missing asynchronous reply bytes: %+v", report)
		}
		<-time.After(20 * time.Millisecond)
	}
}
