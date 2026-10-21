package resolver

import (
	"errors"
	"testing"
)

func TestResponseRuleValidation(t *testing.T) {
	for _, test := range []struct {
		rule  ResponseRule
		valid bool
	}{
		{ResponseRule{Domain: "*.example.com", QueryType: "HTTPS", Rcode: "NXDOMAIN"}, true},
		{ResponseRule{Domain: "*.A.example.com.", QueryType: "AAAA", Rcode: "NOERROR", TTL: 300, Answers: []string{"::1"}}, true},
		{ResponseRule{Domain: "*", QueryType: "*", Rcode: "NOTIMPL"}, true},
		{ResponseRule{Domain: "_service.example", QueryType: "SRV", Rcode: "NOERROR", Answers: []string{"0 5 443 target.example."}}, true},
		{ResponseRule{Domain: "example.com", QueryType: "HTTPS", Rcode: "NOERROR", Answers: []string{`1 . alpn="h2"`}}, true},
		{ResponseRule{Domain: "example.com", QueryType: "MX", Rcode: "NOERROR", Answers: []string{"10 mail.example.com."}}, true},
		{ResponseRule{Domain: "example.com", QueryType: "CNAME", Rcode: "NOERROR", Answers: []string{"target.example.com."}}, true},
		{ResponseRule{Domain: "example.com", QueryType: "TXT", Rcode: "NOERROR", Answers: []string{`"hello world"`}}, true},
		{ResponseRule{Domain: "example.com", QueryType: "A", Rcode: "NOERROR", Answers: []string{"192.0.2.1"}}, true},
		{ResponseRule{Domain: "example.com", QueryType: "A", Rcode: "NOERROR"}, true},
		{ResponseRule{Domain: "a.*.com", QueryType: "A", Rcode: "NOERROR"}, false},
		{ResponseRule{Domain: "https://example.com", QueryType: "A", Rcode: "NOERROR"}, false},
		{ResponseRule{Domain: "example.com", QueryType: "OPT", Rcode: "NOERROR"}, false},
		{ResponseRule{Domain: "example.com", QueryType: "NOPE", Rcode: "NOERROR"}, false},
		{ResponseRule{Domain: "example.com", QueryType: "A", Rcode: "NOERROR", Answers: []string{"::1"}}, false},
		{ResponseRule{Domain: "example.com", QueryType: "AAAA", Rcode: "NOERROR", Answers: []string{"192.0.2.1"}}, false},
		{ResponseRule{Domain: "example.com", QueryType: "A", Rcode: "NXDOMAIN", Answers: []string{"192.0.2.1"}}, false},
		{ResponseRule{Domain: "example.com", QueryType: "*", Rcode: "NOERROR", Answers: []string{"192.0.2.1"}}, false},
		{ResponseRule{Domain: "example.com", QueryType: "A", Rcode: "NOERROR", Answers: []string{"192.0.2.1\nother. IN A 192.0.2.2"}}, false},
		{ResponseRule{Domain: "example.com", QueryType: "AAAA", Rcode: "NOERROR", Answers: []string{""}}, false},
		{ResponseRule{Domain: "example.com", QueryType: "A", Rcode: "NOERROR", TTL: 1 << 31}, false},
		{ResponseRule{Domain: "example.com", QueryType: "A", Rcode: "typo"}, false},
	} {
		t.Run(test.rule.Domain+"/"+test.rule.QueryType+"/"+test.rule.Rcode, func(t *testing.T) {
			err := (ResponseRules{Rules: []ResponseRule{test.rule}}).Validate()
			if (err == nil) != test.valid {
				t.Fatalf("valid = %v, error = %v", test.valid, err)
			}
			if err != nil && !errors.Is(err, ErrInvalidResponseRule) {
				t.Fatal("lost validation error identity")
			}
		})
	}
}
