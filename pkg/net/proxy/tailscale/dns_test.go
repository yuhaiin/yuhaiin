package tailscale

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"go.uber.org/goleak"
	wire "golang.org/x/net/dns/dnsmessage"
	"tailscale.com/control/controlknobs"
	"tailscale.com/health"
	tsdns "tailscale.com/net/dns"
	"tailscale.com/net/netmon"
	"tailscale.com/net/tsdial"
	"tailscale.com/types/dnstype"
	"tailscale.com/util/dnsname"
	"tailscale.com/util/eventbus"
)

func testDNSManager(t *testing.T) *tsdns.Manager {
	t.Helper()
	bus := eventbus.New()
	t.Cleanup(bus.Close)
	nm := netmon.NewStatic()
	t.Cleanup(func() { _ = nm.Close() })
	d := tsdial.NewDialer(nm)
	d.SetBus(bus)
	t.Cleanup(func() { _ = d.Close() })
	noop, err := tsdns.NewNoopManager()
	if err != nil {
		t.Fatal(err)
	}
	m := tsdns.NewManager(t.Logf, noop, health.NewTracker(bus), d, nil, &controlknobs.Knobs{}, "linux", bus)
	t.Cleanup(func() { _ = m.Down() })
	err = m.Set(tsdns.Config{
		Hosts: map[dnsname.FQDN][]netip.Addr{
			"node.test.ts.net.": {netip.MustParseAddr("100.64.0.2"), netip.MustParseAddr("fd7a:115c:a1e0::2")},
			"v6.test.ts.net.":   {netip.MustParseAddr("fd7a:115c:a1e0::3")},
		}, Routes: map[dnsname.FQDN][]*dnstype.Resolver{"test.ts.net.": nil},
	})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func dnsRequest(t *testing.T, id uint16, name string, typ wire.Type) []byte {
	t.Helper()
	m := wire.Message{ID: id, RecursionDesired: true, Questions: []wire.Question{{Name: wire.MustNewName(name), Type: typ, Class: wire.ClassINET}}}
	b, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestDNSPacketManager(t *testing.T) {
	m := testDNSManager(t)
	server := netip.MustParseAddrPort("100.100.100.100:53")
	p := newDNSPacket(t.Context(), m.Query, server)
	defer p.Close()
	for _, tt := range []struct {
		name    string
		typ     wire.Type
		code    wire.RCode
		answers int
	}{
		{"NODE.test.ts.net.", wire.TypeA, wire.RCodeSuccess, 1},
		{"node.test.ts.net.", wire.TypeAAAA, wire.RCodeSuccess, 1},
		{"2.0.64.100.in-addr.arpa.", wire.TypePTR, wire.RCodeSuccess, 1},
		{"missing.test.ts.net.", wire.TypeA, wire.RCodeNameError, 0},
		{"v6.test.ts.net.", wire.TypeA, wire.RCodeSuccess, 0},
		{"v6.test.ts.net.", wire.TypeAAAA, wire.RCodeSuccess, 1},
	} {
		t.Run(tt.name+tt.typ.String(), func(t *testing.T) {
			req := dnsRequest(t, 0x1234, tt.name, tt.typ)
			if _, err := p.WriteTo(req, net.UDPAddrFromAddrPort(server)); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 4096)
			_ = p.SetReadDeadline(time.Now().Add(time.Second))
			n, from, err := p.ReadFrom(buf)
			if err != nil {
				t.Fatal(err)
			}
			var got wire.Message
			if err := got.Unpack(buf[:n]); err != nil {
				t.Fatal(err)
			}
			if got.ID != 0x1234 || got.RCode != tt.code || len(got.Answers) != tt.answers || from.String() != server.String() {
				t.Fatalf("response=%+v from=%v", got, from)
			}
		})
	}
	if _, err := p.WriteTo([]byte("bad DNS"), net.UDPAddrFromAddrPort(server)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	n, _, err := p.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	var malformed wire.Message
	if err := malformed.Unpack(buf[:n]); err != nil {
		t.Fatal(err)
	}
	if malformed.RCode != wire.RCodeFormatError {
		t.Fatalf("malformed query response: %+v", malformed)
	}
}

func TestDNSPacketConcurrent(t *testing.T) {
	m := testDNSManager(t)
	server := netip.MustParseAddrPort("[fd7a:115c:a1e0::53]:53")
	p := newDNSPacket(t.Context(), m.Query, server)
	defer p.Close()
	_ = p.SetDeadline(time.Now().Add(5 * time.Second))
	var wg sync.WaitGroup
	for i := range 32 {
		req := dnsRequest(t, uint16(i), "node.test.ts.net.", wire.TypeAAAA)
		wg.Go(func() {
			if _, err := p.WriteTo(req, net.UDPAddrFromAddrPort(server)); err != nil {
				t.Error(err)
			}
		})
	}
	seen := make(map[uint16]bool)
	for range 32 {
		buf := make([]byte, 4096)
		n, _, err := p.ReadFrom(buf)
		if err != nil {
			t.Fatal(err)
		}
		var m wire.Message
		if err := m.Unpack(buf[:n]); err != nil {
			t.Fatal(err)
		}
		if seen[m.ID] {
			t.Fatalf("duplicate transaction %d", m.ID)
		}
		seen[m.ID] = true
	}
	wg.Wait()
}

func TestDNSPacketErrorsAndClose(t *testing.T) {
	server := netip.MustParseAddrPort("100.100.100.100:53")
	target := net.UDPAddrFromAddrPort(server)
	failure := errors.New("upstream unavailable")
	p := newDNSPacket(t.Context(), func(context.Context, []byte, string, netip.AddrPort) ([]byte, error) { return nil, failure }, server)
	defer p.Close()
	if _, err := p.WriteTo([]byte{1}, target); !errors.Is(err, failure) {
		t.Fatal(err)
	}
	_ = p.SetReadDeadline(time.Now().Add(-time.Second))
	if _, _, err := p.ReadFrom(nil); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal(err)
	}
	_ = p.SetReadDeadline(time.Time{})
	_ = p.SetWriteDeadline(time.Now().Add(-time.Second))
	if _, err := p.WriteTo(nil, target); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal(err)
	}
	_ = p.SetWriteDeadline(time.Time{})
	if _, err := p.WriteTo(nil, &net.UDPAddr{IP: net.IPv4(8, 8, 8, 8), Port: 53}); err == nil {
		t.Fatal("accepted other DNS server")
	}
	_ = p.Close()
	if _, _, err := p.ReadFrom(nil); !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
	if _, err := p.WriteTo(nil, target); !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
	if err := p.SetDeadline(time.Time{}); !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
}

func TestDNSPacketCancelsQuery(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	for _, closeSocket := range []bool{false, true} {
		t.Run(map[bool]string{true: "close", false: "deadline"}[closeSocket], func(t *testing.T) {
			server := netip.MustParseAddrPort("100.100.100.100:53")
			entered := make(chan struct{})
			p := newDNSPacket(t.Context(), func(ctx context.Context, _ []byte, _ string, _ netip.AddrPort) ([]byte, error) {
				close(entered)
				<-ctx.Done()
				return nil, ctx.Err()
			}, server)
			defer p.Close()
			done := make(chan error, 1)
			go func() { _, err := p.WriteTo(nil, net.UDPAddrFromAddrPort(server)); done <- err }()
			<-entered
			want := error(os.ErrDeadlineExceeded)
			if closeSocket {
				_ = p.Close()
				want = net.ErrClosed
			} else {
				_ = p.SetWriteDeadline(time.Now().Add(10 * time.Millisecond))
			}
			select {
			case err := <-done:
				if !errors.Is(err, want) {
					t.Fatalf("got %v want %v", err, want)
				}
			case <-time.After(time.Second):
				t.Fatal("query not canceled")
			}
		})
	}
}

func TestDNSPacketSplitAndDefaultResolvers(t *testing.T) {
	m := testDNSManager(t)
	start := func(answer [4]byte) string {
		t.Helper()
		pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = pc.Close() })
		go func() {
			buf := make([]byte, 4096)
			for {
				n, from, err := pc.ReadFrom(buf)
				if err != nil {
					return
				}
				var q wire.Message
				if q.Unpack(buf[:n]) != nil || len(q.Questions) == 0 {
					continue
				}
				r := wire.Message{ID: q.ID, Response: true, RecursionAvailable: true, Questions: q.Questions,
					Answers: []wire.Resource{{Header: wire.ResourceHeader{Name: q.Questions[0].Name, Class: wire.ClassINET, TTL: 60}, Body: &wire.AResource{A: answer}}}}
				b, err := r.Pack()
				if err == nil {
					_, _ = pc.WriteTo(b, from)
				}
			}
		}()
		return pc.LocalAddr().String()
	}
	split := start([4]byte{192, 0, 2, 1})
	fallback := start([4]byte{192, 0, 2, 2})
	if err := m.Set(tsdns.Config{
		DefaultResolvers: []*dnstype.Resolver{{Addr: fallback}},
		Routes:           map[dnsname.FQDN][]*dnstype.Resolver{"split.test.": {{Addr: split}}},
	}); err != nil {
		t.Fatal(err)
	}
	server := netip.MustParseAddrPort("100.100.100.100:53")
	p := newDNSPacket(t.Context(), m.Query, server)
	defer p.Close()
	_ = p.SetDeadline(time.Now().Add(3 * time.Second))
	for _, tt := range []struct {
		name string
		last byte
	}{{"name.split.test.", 1}, {"ordinary.example.", 2}} {
		if _, err := p.WriteTo(dnsRequest(t, 19, tt.name, wire.TypeA), net.UDPAddrFromAddrPort(server)); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 4096)
		n, _, err := p.ReadFrom(buf)
		if err != nil {
			t.Fatal(err)
		}
		var r wire.Message
		if err := r.Unpack(buf[:n]); err != nil {
			t.Fatal(err)
		}
		if len(r.Answers) != 1 || r.Answers[0].Body.(*wire.AResource).A[3] != tt.last {
			t.Fatalf("%s: %+v", tt.name, r)
		}
	}
}

func TestDNSPacketCloseReleasesBlockedIO(t *testing.T) {
	server := netip.MustParseAddrPort("100.100.100.100:53")
	p := newDNSPacket(t.Context(), func(context.Context, []byte, string, netip.AddrPort) ([]byte, error) { return []byte{1}, nil }, server)
	for range cap(p.replies) {
		if _, err := p.WriteTo(nil, net.UDPAddrFromAddrPort(server)); err != nil {
			t.Fatal(err)
		}
	}
	done := make(chan error, 1)
	go func() { _, err := p.WriteTo(nil, net.UDPAddrFromAddrPort(server)); done <- err }()
	_ = p.Close()
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked writer leaked")
	}
	q := newDNSPacket(t.Context(), nil, server)
	go func() { _, _, err := q.ReadFrom(nil); done <- err }()
	_ = q.Close()
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked reader leaked")
	}
}
