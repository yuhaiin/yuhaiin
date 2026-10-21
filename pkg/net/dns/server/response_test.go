package server

import (
	"bytes"
	"fmt"
	"slices"
	"strings"
	"testing"

	"codeberg.org/miekg/dns"
	contract "github.com/Asutorufa/yuhaiin/pkg/contract/resolver"
	"github.com/Asutorufa/yuhaiin/pkg/net/dns/response"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

func TestCustomResponsesRespectUDPSizeAndPreserveInput(t *testing.T) {
	rules := response.New(netapi.ErrorResolver(func(string) error { return fmt.Errorf("unexpected upstream query") }))
	if err := rules.Apply(contract.ResponseRules{Rules: []contract.ResponseRule{{Domain: "example.com", QueryType: "TXT", Rcode: "NOERROR", TTL: 60, Answers: []string{
		`"` + strings.Repeat("a", 200) + `"`, `"` + strings.Repeat("b", 200) + `"`, `"` + strings.Repeat("c", 200) + `"`, `"` + strings.Repeat("d", 200) + `"`,
	}}}}); err != nil {
		t.Fatal(err)
	}
	agent := NewServer("", rules).(*dnsServer)
	t.Cleanup(func() { _ = agent.Close() })
	for _, test := range []struct {
		size      uint16
		stream    bool
		truncated bool
	}{{0, false, true}, {4096, false, false}, {0, true, false}} {
		q := netapi.NewDNSMsg(netapi.DNSQuestion{Name: "example.com.", Qtype: dns.TypeTXT, Qclass: dns.ClassINET})
		q.Response, q.ID, q.UDPSize = false, 1234, test.size
		if err := q.Pack(); err != nil {
			t.Fatal(err)
		}
		input := slices.Clone(q.Data)
		var output []byte
		if err := agent.do(t.Context(), &doData{Question: input, Stream: test.stream, WriteBack: func(data []byte) error { output = slices.Clone(data); return nil }}); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(input, q.Data) {
			t.Fatal("query buffer was modified")
		}
		decoded := &dns.Msg{Data: output}
		if err := decoded.Unpack(); err != nil {
			t.Fatal(err)
		}
		if decoded.ID != 1234 || decoded.Truncated != test.truncated {
			t.Fatal("response flags were not preserved")
		}
		if test.truncated {
			if len(decoded.Answer) != 0 || len(output) > 512 {
				t.Fatal("UDP response was not truncated")
			}
		} else if len(decoded.Answer) != 4 {
			t.Fatal("full response was lost")
		}
	}
}
