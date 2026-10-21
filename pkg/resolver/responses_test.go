package resolver

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	contract "github.com/Asutorufa/yuhaiin/pkg/contract/resolver"
	"github.com/Asutorufa/yuhaiin/pkg/net/dns/response"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	"github.com/Asutorufa/yuhaiin/pkg/store"
)

func TestResponseRulesPersistActivateAndReload(t *testing.T) {
	db, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	raw := store.NewResolverConfigStore(db.DB())
	rules := response.New(netapi.ErrorResolver(func(string) error { return fmt.Errorf("unexpected upstream query") }))
	c := &ResolverCtr{config: raw, responses: rules}
	controller := NewContractConfigController(c)
	facade := store.NewResolverConfigRuntimeStore(raw, controller)
	config := contract.ResponseRules{Rules: []contract.ResponseRule{{Domain: "*.example.com", QueryType: "AAAA", Rcode: "NOERROR", TTL: 120, Answers: []string{"::1"}}}}
	if _, err := facade.SaveResponseRules(t.Context(), config); err != nil {
		t.Fatal(err)
	}
	check := func(resolver netapi.Resolver) {
		t.Helper()
		msg, err := resolver.Raw(t.Context(), netapi.DNSQuestion{Name: "x.example.com.", Qtype: dns.TypeAAAA, Qclass: dns.ClassINET})
		if err != nil || len(msg.Answer) != 1 || msg.Answer[0].(*dns.AAAA).Addr != netip.IPv6Loopback() {
			t.Fatalf("response = %v, %v", msg, err)
		}
	}
	check(rules)
	loaded, err := raw.ResponseRules(t.Context())
	if err != nil || !reflect.DeepEqual(loaded, config) {
		t.Fatalf("saved rules = %+v, %v", loaded, err)
	}
	invalid := contract.ResponseRules{Rules: []contract.ResponseRule{{Domain: "*", QueryType: "AAAA", Rcode: "NOERROR", Answers: []string{"invalid"}}}}
	if _, err := facade.SaveResponseRules(t.Context(), invalid); err == nil {
		t.Fatal("invalid update succeeded")
	}
	check(rules)
	loaded, _ = raw.ResponseRules(t.Context())
	if !reflect.DeepEqual(loaded, config) {
		t.Fatal("invalid update overwrote storage")
	}

	// Restore the rules through the same initialization path as application startup.
	fake, err := NewFakeDNS(nil, rules, filepath.Join(t.TempDir(), "fake.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fake.Close() })
	reloaded := response.New(fake)
	server := NewDNSServer(reloaded)
	t.Cleanup(func() { _ = server.Close() })
	_ = NewResolverCtr(nil, raw, NewHosts(nil, nil), fake, nil, reloaded, server)
	check(reloaded)

	var wg sync.WaitGroup
	for i := range 10 {
		wg.Go(func() {
			next := contract.ResponseRules{Rules: []contract.ResponseRule{{Domain: "*.example.com", QueryType: "AAAA", Rcode: "NOERROR", Answers: []string{fmt.Sprintf("2001:db8::%x", i+1)}}}}
			if _, err := facade.SaveResponseRules(t.Context(), next); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	loaded, err = raw.ResponseRules(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	msg, err := rules.Raw(t.Context(), netapi.DNSQuestion{Name: "x.example.com.", Qtype: dns.TypeAAAA, Qclass: dns.ClassINET})
	if err != nil || msg.Answer[0].(*dns.AAAA).Addr.String() != loaded.Rules[0].Answers[0] {
		t.Fatal("runtime and persisted rules diverged")
	}
}

func TestCustomResponseBeforeFakeIPAndHostsOverDNSStream(t *testing.T) {
	hosts := NewHosts(nil, netapi.ErrorResolver(func(string) error { return fmt.Errorf("unexpected upstream query") }))
	hosts.Apply(map[string]string{"x.example.com": "2001:db8::5"})
	fake, err := NewFakeDNS(nil, hosts, filepath.Join(t.TempDir(), "fake.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fake.Close() })
	if err := fake.Apply(contract.FakeDNS{Enabled: true, SkipCheckList: []string{"*.example.com"}}); err != nil {
		t.Fatal(err)
	}
	rules := response.New(fake)
	if err := rules.Apply(contract.ResponseRules{Rules: []contract.ResponseRule{
		{Domain: "*.example.com", QueryType: "HTTPS", Rcode: "NXDOMAIN"},
		{Domain: "*.example.com", QueryType: "AAAA", Rcode: "NOERROR", TTL: 60, Answers: []string{"::1"}},
	}}); err != nil {
		t.Fatal(err)
	}
	server := NewDNSServer(rules)
	t.Cleanup(func() { _ = server.Close() })
	for _, typ := range []uint16{dns.TypeHTTPS, dns.TypeAAAA, dns.TypeA} {
		client, conn := net.Pipe()
		_ = client.SetDeadline(time.Now().Add(3 * time.Second))
		q := netapi.DNSQuestion{Name: "x.example.com.", Qtype: typ, Qclass: dns.ClassINET}
		request := netapi.NewDNSMsg(q)
		request.Response, request.ID = false, 42
		if err := request.Pack(); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- server.DoStream(t.Context(), &netapi.DNSStreamRequest{Conn: conn, ForceFakeIP: true}) }()
		data := binary.BigEndian.AppendUint16(nil, uint16(len(request.Data)))
		data = append(data, request.Data...)
		if _, err := client.Write(data); err != nil {
			t.Fatal(err)
		}
		var length uint16
		if err := binary.Read(client, binary.BigEndian, &length); err != nil {
			t.Fatal(err)
		}
		msg := &dns.Msg{Data: make([]byte, length)}
		if _, err := io.ReadFull(client, msg.Data); err != nil {
			t.Fatal(err)
		}
		_ = client.Close()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if err := msg.Unpack(); err != nil {
			t.Fatal(err)
		}
		if msg.ID != 42 || !msg.Response {
			t.Fatal("incorrect wire response")
		}
		switch typ {
		case dns.TypeHTTPS:
			if msg.Rcode != dns.RcodeNameError || len(msg.Answer) != 0 {
				t.Fatal("HTTPS was not blocked")
			}
		case dns.TypeAAAA:
			if len(msg.Answer) != 1 || msg.Answer[0].(*dns.AAAA).Addr != netip.IPv6Loopback() {
				t.Fatal("custom answer lost precedence")
			}
		case dns.TypeA:
			if len(msg.Answer) == 0 || !fake.FakeIPRanges()[0].Contains(msg.Answer[0].(*dns.A).Addr) {
				t.Fatal("unmatched question did not reach FakeIP")
			}
		}
	}
}
