// Package accesscontrol authorizes authenticated traffic independently of route
// actions. It reuses the routing condition compiler and never queries storage.
package accesscontrol

import (
	"encoding/json/v2"
	"fmt"
	"strconv"
	"strings"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/access"
	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/route"
)

type compiledRule struct {
	id    string
	allow bool
	match route.Matcher
}
type Prepared struct {
	config   contract.Config
	inbounds map[string]struct{}
	rules    []compiledRule
}

func Prepare(config contract.Config) (*Prepared, error) {
	if len(config.Rules) > 1024 || len(config.Scope.Inbounds) > 1024 {
		return nil, fmt.Errorf("access policy is too large")
	}
	if config.Enabled && config.Scope.AllInbounds == (len(config.Scope.Inbounds) > 0) {
		return nil, fmt.Errorf("select all inbounds or an explicit nonempty inbound scope")
	}
	if config.DefaultAction != "allow" && config.DefaultAction != "deny" {
		return nil, fmt.Errorf("choose an explicit allow or deny default")
	}
	remaining, terms := 4096, 16384
	seen := make(map[string]bool, len(config.Rules))
	for _, rule := range config.Rules {
		if strings.TrimSpace(rule.ID) == "" || len(rule.ID) > 128 || len(rule.Name) > 128 || seen[rule.ID] {
			return nil, fmt.Errorf("invalid or duplicate access rule ID")
		}
		seen[rule.ID] = true
		if rule.Action != "allow" && rule.Action != "deny" {
			return nil, fmt.Errorf("access rule %s: action must be allow or deny", rule.ID)
		}
		if err := contractroute.ValidateConditions(rule.Conditions); err != nil {
			return nil, fmt.Errorf("access rule %s: %w", rule.ID, err)
		}
		for _, expr := range rule.Conditions {
			if err := validateAccessExpr(expr, &remaining, &terms); err != nil {
				return nil, fmt.Errorf("access rule %s: %w", rule.ID, err)
			}
		}
	}
	// Detach caller-owned slices and Not pointers before publication. This only
	// happens on the management path, never once per connection or packet.
	data, err := json.Marshal(config)
	if err != nil {
		return nil, err
	}
	var copied contract.Config
	if err := json.Unmarshal(data, &copied); err != nil {
		return nil, err
	}
	p := &Prepared{config: copied, inbounds: make(map[string]struct{}, len(copied.Scope.Inbounds))}
	for _, id := range copied.Scope.Inbounds {
		if strings.TrimSpace(id) == "" || len(id) > 128 {
			return nil, fmt.Errorf("invalid inbound scope")
		}
		p.inbounds[id] = struct{}{}
	}
	for _, rule := range copied.Rules {
		if !rule.Disabled {
			p.rules = append(p.rules, compiledRule{id: rule.ID, allow: rule.Action == "allow", match: route.ParseMatcher(contractroute.RouteRule{Rules: rule.Conditions})})
		}
	}
	return p, nil
}

func validateAccessExpr(expr contractroute.RuleExpr, remaining, terms *int) error {
	*remaining -= 1
	if *remaining < 0 {
		return fmt.Errorf("access policies allow at most 4096 condition nodes")
	}
	n := 0
	switch expr.Type {
	case "all":
		for _, child := range expr.All {
			if err := validateAccessExpr(child, remaining, terms); err != nil {
				return err
			}
		}
	case "any":
		for _, child := range expr.Any {
			if err := validateAccessExpr(child, remaining, terms); err != nil {
				return err
			}
		}
	case "not":
		return validateAccessExpr(*expr.Not, remaining, terms)
	case "user":
		n = len(expr.User.IDs)
	case "group":
		n = len(expr.Group.IDs)
	case "credential":
		n = len(expr.Credential.IDs)
	case "inbound":
		n = len(expr.Inbound.Names) + 1
	case "destination":
		n = len(expr.Destination.Domains) + len(expr.Destination.CIDRs)
	case "port":
		// The shared route compiler expands port ranges. Charge expanded values
		// before compiling to bound memory even for thousands of broad ranges.
		for part := range strings.SplitSeq(expr.Port.Ports, ",") {
			first, last, ranged := strings.Cut(strings.TrimSpace(part), "-")
			start, _ := strconv.ParseUint(first, 10, 16)
			end := start
			if ranged {
				end, _ = strconv.ParseUint(last, 10, 16)
			}
			n += int(end-start) + 1
		}
	case "always", "network":
	default:
		return fmt.Errorf("condition %s is unsupported in traffic access policies", expr.Type)
	}
	*terms -= n
	if *terms < 0 {
		return fmt.Errorf("access policies allow at most 16384 condition values")
	}
	return nil
}

func (p *Prepared) managed(subject netapi.TrafficSubject) bool {
	if !subject.External || !p.config.Enabled {
		return false
	}
	if subject.InboundID == "" {
		return true
	}
	if p.config.Scope.AllInbounds {
		return true
	}
	_, ok := p.inbounds[subject.InboundID]
	return ok
}

func (p *Prepared) Config() contract.Config {
	data, _ := json.Marshal(p.config)
	var out contract.Config
	_ = json.Unmarshal(data, &out)
	return out
}
