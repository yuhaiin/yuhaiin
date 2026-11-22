package statistics_test

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	contract "github.com/Asutorufa/yuhaiin/pkg/contract/dnshistory"
	"github.com/Asutorufa/yuhaiin/pkg/net/dns/resolver"
	"github.com/Asutorufa/yuhaiin/pkg/net/dns/server"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/statistics"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
)

type liveDNS struct {
	history *statistics.DNSHistory
	store   *sqlite.Store
	udp     string
	tcp     string
}

func freePort(t *testing.T) string {
	l, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.LocalAddr().String()
	_ = l.Close()
	return addr
}

func startLiveDNS(t *testing.T) *liveDNS {
	t.Helper()
	store, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	h, err := statistics.NewDNSHistory(store.DB(), statistics.DNSHistoryOptions{FlushInterval: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	upstream := resolver.NewClient(resolver.Config{Name: "live", Type: "udp"}, resolver.TransportFunc(func(_ context.Context, req *resolver.Request) (*dns.Msg, error) {
		return &dns.Msg{ID: req.ID, Response: true, Answer: []dns.RR{&dns.A{Hdr: dns.Header{Name: req.Question.Name, Class: dns.ClassINET, TTL: 1}, Addr: netip.MustParseAddr("192.0.2.80")}}}, nil
	}))
	addr := freePort(t)
	agent := server.NewServer(addr, upstream, h)
	t.Cleanup(func() { _ = agent.Close(); _ = h.Close(); _ = upstream.Close(); _ = store.Close() })
	return &liveDNS{history: h, store: store, udp: addr, tcp: addr}
}

func (l *liveDNS) exchange(t *testing.T, network, name string) {
	t.Helper()
	q := netapi.NewDNSMsg(netapi.DNSQuestion{Name: name, Qtype: dns.TypeA, Qclass: dns.ClassINET})
	q.Response = false
	if err := q.Pack(); err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial(network, l.udp)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	var reply []byte
	if network == "tcp" {
		_ = binary.Write(conn, binary.BigEndian, uint16(len(q.Data)))
		_, _ = conn.Write(q.Data)
		var n uint16
		if err := binary.Read(conn, binary.BigEndian, &n); err != nil {
			t.Fatal(err)
		}
		reply = make([]byte, n)
		if _, err := io.ReadFull(conn, reply); err != nil {
			t.Fatal(err)
		}
	} else {
		_, _ = conn.Write(q.Data)
		buf := make([]byte, 1500)
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		reply = buf[:n]
	}
	m := &dns.Msg{Data: reply}
	if err := m.Unpack(); err != nil || len(m.Answer) != 1 {
		t.Fatalf("%s reply: %v %v", network, err, m)
	}
}

func (l *liveDNS) waitAccounted(t *testing.T, n uint64) contract.RecorderStatus {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		s := l.history.Status()
		if s.Persisted+s.PersistenceErrors >= n || time.Now().After(deadline) {
			return s
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestDNSHistoryLiveServerRecordsUDPAndTCP(t *testing.T) {
	l := startLiveDNS(t)
	l.exchange(t, "udp", "udp.example.")
	l.exchange(t, "tcp", "tcp.example.")
	l.waitAccounted(t, 2)
	page, err := l.history.List(t.Context(), contract.ListRequest{SourceType: netapi.DNSSourceLocal})
	if err != nil || page.Total != 2 {
		t.Fatalf("page = %+v %v", page, err)
	}
	for _, item := range page.Items {
		if item.Outcome != "success" || item.ClientIP != "127.0.0.1" || item.Resolver != "live" || item.SentBytes != item.ResponseSize || item.AnswerSummary != "192.0.2.80" {
			t.Fatalf("item = %+v", item)
		}
	}
}

func TestDNSHistoryDisabledRecordsNothing(t *testing.T) {
	l := startLiveDNS(t)
	if _, err := l.history.SaveSettings(t.Context(), contract.Settings{Enabled: false, RetentionHours: 1, MaxRecords: 100}); err != nil {
		t.Fatal(err)
	}
	l.exchange(t, "udp", "quiet.example.")
	time.Sleep(50 * time.Millisecond)
	if page, _ := l.history.List(t.Context(), contract.ListRequest{}); page.Total != 0 {
		t.Fatalf("disabled history recorded %d", page.Total)
	}
}

func TestDNSHistoryStorageFailureDoesNotAffectDNS(t *testing.T) {
	l := startLiveDNS(t)
	if _, err := l.store.DB().ExecContext(t.Context(), `DROP TABLE dns_query_history`); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"one.example.", "two.example.", "three.example."} {
		l.exchange(t, "udp", name)
	}
	if s := l.waitAccounted(t, 3); s.PersistenceErrors != 3 {
		t.Fatalf("status = %+v", s)
	}
}
