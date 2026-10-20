package gateway

import (
	"fmt"
	"net/http/httptest"
	"testing"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/gateway"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

func TestMultiValueConditionMatches(t *testing.T) {
	cases := []struct {
		name  string
		match contract.Condition
		url   string
		want  bool
	}{
		{"path prefix", contract.Condition{Field: "path", Operator: "prefix", Values: []string{"/admin/", "/api/"}}, "http://host/api/item", true},
		{"path misses", contract.Condition{Field: "path", Operator: "prefix", Values: []string{"/admin/", "/api/"}}, "http://host/public", false},
		{"domain", contract.Condition{Field: "host", Operator: "domain", Values: []string{"example.com", "example.org"}}, "http://sub.example.org/", true},
		{"exact", contract.Condition{Field: "path", Values: []string{"/one", "/two"}}, "http://host/two", true},
		{"suffix", contract.Condition{Field: "path", Operator: "suffix", Values: []string{".js", ".css"}}, "http://host/main.css", true},
		{"regex", contract.Condition{Field: "path", Operator: "regex", Values: []string{"^/foo/[0-9]+$", "^/bar/[a-z]+$"}}, "http://host/bar/abc", true},
		{"AND of OR leaves", contract.Condition{All: []contract.Condition{
			{Field: "host", Operator: "domain", Values: []string{"example.com", "example.org"}},
			{Field: "path", Operator: "prefix", Values: []string{"/api", "/admin"}},
		}}, "http://example.org/admin/x", true},
		{"NOT of multiple values", contract.Condition{Not: &contract.Condition{Field: "path", Values: []string{"/one", "/two"}}}, "http://host/two", false},
		{"NOT otherwise", contract.Condition{Not: &contract.Condition{Field: "path", Values: []string{"/one", "/two"}}}, "http://host/three", true},
		{"legacy Go input", contract.Condition{Field: "path", Value: "/old"}, "http://host/old", true},
	}
	ctx := netapi.WithContext(t.Context())
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			match, err := compileCondition(tc.match, 0)
			if err != nil {
				t.Fatal(err)
			}
			if got := match(httptest.NewRequest("GET", tc.url, nil), ctx); got != tc.want {
				t.Fatalf("matched %v, want %v", got, tc.want)
			}
		})
	}
}

func TestMultiValueConditionRejectsInvalidLeaves(t *testing.T) {
	cases := []contract.Condition{
		{Field: "path"},
		{Field: "path", Values: []string{""}},
		{Field: "path", Operator: "present", Values: []string{"/"}},
		{Field: "path", Operator: "regex", Values: []string{"^/safe$", "["}},
	}
	for i, c := range cases {
		if _, err := compileCondition(c, 0); err == nil {
			t.Errorf("case %d unexpectedly accepted", i)
		}
	}
}

func TestMultiValueHeadersAndQuery(t *testing.T) {
	ctx := netapi.WithContext(t.Context())
	r := httptest.NewRequest("GET", "http://host/?mode=red&mode=blue", nil)
	r.Header.Add("X-Group", "one")
	r.Header.Add("X-Group", "two")
	for _, c := range []contract.Condition{
		{Field: "query", Key: "mode", Values: []string{"green", "blue"}},
		{Field: "header", Key: "X-Group", Values: []string{"three", "two"}},
	} {
		match, err := compileCondition(c, 0)
		if err != nil {
			t.Fatal(err)
		}
		if !match(r, ctx) {
			t.Fatalf("query/header values did not match: %+v", c)
		}
	}
}

func BenchmarkConditionMultiValues(b *testing.B) {
	for _, operator := range []string{"exact", "prefix", "regex"} {
		for _, n := range []int{1, 10, 100} {
			b.Run(fmt.Sprintf("%s/%d", operator, n), func(b *testing.B) {
				values := make([]string, n)
				for i := range values {
					if operator == "regex" {
						values[i] = fmt.Sprintf("^/other/%d$", i)
					} else {
						values[i] = fmt.Sprintf("/other/%d", i)
					}
				}
				if operator == "regex" {
					values[n-1] = "^/matched$"
				} else {
					values[n-1] = "/matched"
				}
				match, err := compileCondition(contract.Condition{Field: "path", Operator: operator, Values: values}, 0)
				if err != nil {
					b.Fatal(err)
				}
				r := httptest.NewRequest("GET", "http://host/matched", nil)
				ctx := netapi.WithContext(b.Context())
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if !match(r, ctx) {
						b.Fatal("unexpected miss")
					}
				}
			})
		}
	}
}
