package resolver

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

var ErrInvalidResponseRule = errors.New("invalid DNS response rule")

// ResponseRule matches a question and synthesizes a complete answer. Answers
// contain record data in DNS presentation format, without owner, TTL or type.
type ResponseRule struct {
	Domain    string   `json:"domain"`
	QueryType string   `json:"queryType"`
	Rcode     string   `json:"rcode"`
	TTL       uint32   `json:"ttl"`
	Answers   []string `json:"answers"`
}

// ResponseRules uses first-match order, including overlaps between exact names,
// wildcard names and query types. An empty list disables custom responses.
type ResponseRules struct {
	Rules []ResponseRule `json:"rules"`
}

type ResponseRulesController interface {
	ResponseRules(context.Context) (ResponseRules, error)
	SaveResponseRules(context.Context, ResponseRules) (ResponseRules, error)
}

func (r ResponseRule) Records() ([]dns.RR, error) {
	name := strings.TrimSuffix(strings.TrimPrefix(r.Domain, "*."), ".")
	if r.Domain != "*" && (name == "" || strings.ContainsAny(name, "*:/\\ \t\r\n;?#@") || !dnsutil.IsName(name)) {
		return nil, fmt.Errorf("%w: invalid domain %q", ErrInvalidResponseRule, r.Domain)
	}
	typ, ok := dns.StringToType[r.QueryType]
	if r.QueryType != "*" && (!ok || typ == dns.TypeNone || typ == dns.TypeOPT || typ == dns.TypeTSIG || typ == dns.TypeAXFR || typ == dns.TypeIXFR) {
		return nil, fmt.Errorf("%w: unsupported query type %q", ErrInvalidResponseRule, r.QueryType)
	}
	switch r.Rcode {
	case "NOERROR", "NXDOMAIN", "REFUSED", "SERVFAIL", "FORMERR", "NOTIMPL":
	default:
		return nil, fmt.Errorf("%w: unsupported response code %q", ErrInvalidResponseRule, r.Rcode)
	}
	if len(r.Answers) > 0 && (r.Rcode != "NOERROR" || r.QueryType == "*" || typ == dns.TypeANY) {
		return nil, fmt.Errorf("%w: answers require NOERROR and a concrete record type", ErrInvalidResponseRule)
	}
	if r.TTL > 1<<31-1 {
		return nil, fmt.Errorf("%w: TTL must be at most 2147483647", ErrInvalidResponseRule)
	}
	records := make([]dns.RR, 0, len(r.Answers))
	for _, value := range r.Answers {
		if strings.TrimSpace(value) == "" || strings.ContainsAny(value, "\r\n") {
			return nil, fmt.Errorf("%w: record data must be non-empty and on one line", ErrInvalidResponseRule)
		}
		rr, err := dns.New(fmt.Sprintf("response.invalid. %d IN %s %s", r.TTL, r.QueryType, value))
		if err != nil || rr == nil || dns.RRToType(rr) != typ {
			return nil, fmt.Errorf("%w: invalid %s data %q: %v", ErrInvalidResponseRule, r.QueryType, value, err)
		}
		msg := &dns.Msg{Answer: []dns.RR{rr}}
		if err := msg.Pack(); err != nil {
			return nil, fmt.Errorf("%w: invalid record: %v", ErrInvalidResponseRule, err)
		}
		records = append(records, rr)
	}
	return records, nil
}

func (r ResponseRules) Validate() error {
	for i, rule := range r.Rules {
		if _, err := rule.Records(); err != nil {
			return fmt.Errorf("rule %d: %w", i+1, err)
		}
	}
	return nil
}
