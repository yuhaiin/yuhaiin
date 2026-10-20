// Package gateway implements request policy independently of L4 routing.
package gateway

import (
	"cmp"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/gateway"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"golang.org/x/net/http/httpguts"
)

type condition func(*http.Request, *netapi.Context) bool
type compiledRule struct {
	rule  contract.Rule
	match condition
}

type Policy struct {
	needsProcess bool
	rules        []compiledRule
	fallback     contract.Action
}

// CompilePolicy owns a deep copy. Callers can edit drafts after compilation.
func CompilePolicy(rules []contract.Rule, fallback contract.Action) (*Policy, error) {
	data, err := json.Marshal(rules)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &rules); err != nil {
		return nil, err
	}
	data, err = json.Marshal(fallback)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &fallback); err != nil {
		return nil, err
	}
	p := &Policy{fallback: fallback}
	if err := validateAction(fallback); err != nil {
		return nil, fmt.Errorf("default action: %w", err)
	}
	slices.SortFunc(rules, func(a, b contract.Rule) int {
		return cmp.Or(cmp.Compare(a.Priority, b.Priority), strings.Compare(a.ID, b.ID))
	})
	seen := map[string]bool{}
	for _, rule := range rules {
		if rule.ID == "" || seen[rule.ID] {
			return nil, errors.New("rule IDs must be nonempty and unique")
		}
		seen[rule.ID] = true
		if err := validateAction(rule.Action); err != nil {
			return nil, fmt.Errorf("rule %s: %w", rule.ID, err)
		}
		match, err := compileCondition(rule.Match, 0)
		if err != nil {
			return nil, fmt.Errorf("rule %s: %w", rule.ID, err)
		}
		if rule.Enabled {
			p.needsProcess = p.needsProcess || conditionUsesField(rule.Match, "process")
			p.rules = append(p.rules, compiledRule{rule, match})
		}
	}
	return p, nil
}

func conditionUsesField(c contract.Condition, field string) bool {
	if c.Field == field {
		return true
	}
	for _, child := range c.All {
		if conditionUsesField(child, field) {
			return true
		}
	}
	for _, child := range c.Any {
		if conditionUsesField(child, field) {
			return true
		}
	}
	return c.Not != nil && conditionUsesField(*c.Not, field)
}

func (p *Policy) evaluate(r *http.Request, ctx *netapi.Context, trace bool) contract.TestResult {
	result := contract.TestResult{Action: p.fallback, Steps: []contract.MatchStep{}}
	for _, rule := range p.rules {
		matched := rule.match(r, ctx)
		if trace {
			result.Steps = append(result.Steps, contract.MatchStep{RuleID: rule.rule.ID, Name: rule.rule.Name, Matched: matched})
		}
		if matched {
			result.RuleID = rule.rule.ID
			result.Action = rule.rule.Action
			break
		}
	}
	return result
}

func compileCondition(c contract.Condition, depth int) (condition, error) {
	c = contract.NormalizeCondition(c)
	if depth > 16 {
		return nil, errors.New("condition nesting exceeds 16")
	}
	n := 0
	if len(c.All) > 0 {
		n++
	}
	if len(c.Any) > 0 {
		n++
	}
	if c.Not != nil {
		n++
	}
	if c.Field != "" {
		n++
	}
	if n == 0 {
		return func(*http.Request, *netapi.Context) bool { return true }, nil
	}
	if n != 1 {
		return nil, errors.New("condition requires exactly one of all, any, not, field")
	}
	if c.Not != nil {
		f, err := compileCondition(*c.Not, depth+1)
		if err != nil {
			return nil, err
		}
		return func(r *http.Request, ctx *netapi.Context) bool { return !f(r, ctx) }, nil
	}
	if len(c.All) > 0 || len(c.Any) > 0 {
		children := c.All
		all := len(c.All) > 0
		if !all {
			children = c.Any
		}
		if len(children) > 256 {
			return nil, errors.New("too many condition children")
		}
		fs := make([]condition, 0, len(children))
		for _, child := range children {
			f, err := compileCondition(child, depth+1)
			if err != nil {
				return nil, err
			}
			fs = append(fs, f)
		}
		return func(r *http.Request, ctx *netapi.Context) bool {
			for _, f := range fs {
				if f(r, ctx) != all {
					return !all
				}
			}
			return all
		}, nil
	}
	var get func(*http.Request, *netapi.Context) []string
	var scalar func(*http.Request, *netapi.Context) string
	switch c.Field {
	case "host":
		scalar = func(r *http.Request, _ *netapi.Context) string { return hostname(r.Host) }
	case "path":
		scalar = func(r *http.Request, _ *netapi.Context) string { return r.URL.Path }
	case "url":
		scalar = func(r *http.Request, _ *netapi.Context) string { return r.URL.String() }
	case "method":
		scalar = func(r *http.Request, _ *netapi.Context) string { return r.Method }
	case "header":
		if !httpguts.ValidHeaderFieldName(c.Key) {
			return nil, errors.New("invalid header key")
		}
		get = func(r *http.Request, _ *netapi.Context) []string { return r.Header.Values(c.Key) }
	case "query":
		if c.Key == "" {
			return nil, errors.New("query key is required")
		}
		get = func(r *http.Request, _ *netapi.Context) []string { return r.URL.Query()[c.Key] }
	case "inbound":
		scalar = func(_ *http.Request, ctx *netapi.Context) string { return ctx.GetInboundID() }
	case "process":
		scalar = func(_ *http.Request, ctx *netapi.Context) string { return ctx.GetProcessName() }
	default:
		return nil, fmt.Errorf("unsupported HTTP condition field %q", c.Field)
	}
	if c.Operator == "present" {
		if len(c.Values) != 0 {
			return nil, errors.New("present operator does not accept values")
		}
		if scalar != nil {
			return func(r *http.Request, ctx *netapi.Context) bool { return scalar(r, ctx) != "" }, nil
		}
		return func(r *http.Request, ctx *netapi.Context) bool { return len(get(r, ctx)) > 0 }, nil
	}
	if len(c.Values) == 0 {
		return nil, errors.New("condition requires at least one value")
	}
	if len(c.Values) > 256 {
		return nil, errors.New("too many condition values")
	}
	if slices.Contains(c.Values, "") {
		return nil, errors.New("condition values must be nonempty")
	}
	// Values within a leaf always use OR; the surrounding condition tree
	// continues to determine AND/OR/NOT across distinct fields.
	var test func(string) bool
	switch c.Operator {
	case "", "exact":
		if len(c.Values) == 1 {
			value := c.Values[0]
			test = func(v string) bool { return v == value }
		} else {
			set := make(map[string]struct{}, len(c.Values))
			for _, value := range c.Values {
				set[value] = struct{}{}
			}
			test = func(v string) bool {
				_, ok := set[v]
				return ok
			}
		}
	case "prefix":
		values := c.Values
		test = func(v string) bool {
			return slices.ContainsFunc(values, func(value string) bool { return strings.HasPrefix(v, value) })
		}
	case "suffix":
		values := c.Values
		test = func(v string) bool {
			return slices.ContainsFunc(values, func(value string) bool { return strings.HasSuffix(v, value) })
		}
	case "domain":
		values := make([]string, len(c.Values))
		for i, value := range c.Values {
			values[i] = hostname(value)
		}
		test = func(v string) bool {
			return slices.ContainsFunc(values, func(value string) bool { return domainMatches(v, value) })
		}
	case "regex":
		rxs := make([]*regexp.Regexp, 0, len(c.Values))
		for _, value := range c.Values {
			if len(value) > 4096 {
				return nil, errors.New("regex exceeds 4096 bytes")
			}
			re, err := regexp.Compile(value)
			if err != nil {
				return nil, err
			}
			rxs = append(rxs, re)
		}
		test = func(v string) bool {
			return slices.ContainsFunc(rxs, func(re *regexp.Regexp) bool { return re.MatchString(v) })
		}
	default:
		return nil, fmt.Errorf("unsupported condition operator %q", c.Operator)
	}
	if scalar != nil {
		return func(r *http.Request, ctx *netapi.Context) bool { return test(scalar(r, ctx)) }, nil
	}
	return func(r *http.Request, ctx *netapi.Context) bool {
		return slices.ContainsFunc(get(r, ctx), test)
	}, nil
}

func hostname(authority string) string {
	if strings.ContainsRune(authority, ':') && (!strings.HasPrefix(authority, "[") || !strings.HasSuffix(authority, "]")) {
		if h, _, err := net.SplitHostPort(authority); err == nil {
			authority = h
		}
	}
	return strings.ToLower(strings.TrimSuffix(strings.Trim(authority, "[]"), "."))
}

func domainMatches(host, domain string) bool {
	return host == domain || (len(host) > len(domain) && host[len(host)-len(domain)-1] == '.' && strings.HasSuffix(host, domain))
}

func validateAction(a contract.Action) error {
	switch a.Type {
	case "forward", "rewrite":
	case "reverse_proxy":
		if a.Upstream == "" {
			return errors.New("reverse proxy requires an upstream")
		}
	case "block", "respond":
		if a.Status != 0 && (a.Status < 200 || a.Status > 599) {
			return errors.New("response status must be 200..599")
		}
	case "redirect":
		if !slices.Contains([]int{301, 302, 307, 308}, a.Status) {
			return errors.New("redirect status must be 301, 302, 307 or 308")
		}
		u, err := url.Parse(a.Location)
		if err != nil || a.Location == "" || strings.ContainsAny(a.Location, "\r\n") || u.User != nil || (u.IsAbs() && u.Scheme != "http" && u.Scheme != "https") {
			return errors.New("invalid redirect location")
		}
	default:
		return fmt.Errorf("unsupported action %q", a.Type)
	}
	switch a.Outbound.Type {
	case "", "inherit_route", "direct", "default":
		if a.Outbound.ID != "" {
			return errors.New("outbound ID requires node or selector")
		}
	case "node", "selector":
		if a.Outbound.ID == "" {
			return errors.New("outbound ID is required")
		}
	default:
		return errors.New("unsupported outbound type")
	}
	if a.Rewrite.Scheme != "" && a.Rewrite.Scheme != "http" && a.Rewrite.Scheme != "https" {
		return errors.New("rewrite scheme must be http or https")
	}
	if a.Rewrite.Host != "" {
		u, err := url.Parse("https://" + a.Rewrite.Host)
		if err != nil || u.Host != a.Rewrite.Host || u.User != nil || u.Hostname() == "" {
			return errors.New("invalid rewrite host")
		}
	}
	if a.Rewrite.Path != "" && !strings.HasPrefix(a.Rewrite.Path, "/") {
		return errors.New("rewrite path must start with /")
	}
	if err := validateHeaders(a.Rewrite.Headers); err != nil {
		return err
	}
	return validateHeaders(a.ResponseHeaders)
}

func validateHeaders(headers http.Header) error {
	for k, vs := range headers {
		if !httpguts.ValidHeaderFieldName(k) {
			return errors.New("invalid header name")
		}
		switch strings.ToLower(k) {
		case "connection", "upgrade", "transfer-encoding", "content-length", "host", "proxy-authorization", "proxy-authenticate", "keep-alive", "te", "trailer":
			return fmt.Errorf("header %s is managed by HTTP transport", k)
		}
		for _, v := range vs {
			if !httpguts.ValidHeaderFieldValue(v) {
				return fmt.Errorf("invalid value for header %s", k)
			}
		}
	}
	return nil
}
