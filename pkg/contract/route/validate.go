package route

import (
	"fmt"
	"strconv"
	"strings"
)

// ValidateConditions defines the condition language independently of its
// runtime representation. An empty group is never an implicit match-all.
func ValidateConditions(rules []RuleExpr) error {
	if len(rules) == 0 {
		return fmt.Errorf("add a condition or explicitly choose all traffic")
	}
	remaining := 4096
	for i, rule := range rules {
		if err := validateExpr(rule, 0, &remaining); err != nil {
			return fmt.Errorf("conditions[%d]: %w", i, err)
		}
	}
	return nil
}

func validateExpr(expr RuleExpr, depth int, remaining *int) error {
	*remaining -= 1
	if depth > 32 || *remaining < 0 {
		return fmt.Errorf("condition expression is too large")
	}
	fields := 0
	for _, present := range []bool{expr.Always != nil, expr.All != nil, expr.Any != nil, expr.Not != nil, expr.Host != nil, expr.Process != nil, expr.Inbound != nil, expr.Network != nil, expr.Port != nil, expr.GeoIP != nil, expr.User != nil, expr.Group != nil, expr.Credential != nil} {
		if present {
			fields++
		}
	}
	if expr.Type == "always" {
		if fields > 1 || fields == 1 && expr.Always == nil {
			return fmt.Errorf("all-traffic condition cannot contain other conditions")
		}
		return nil
	}
	if fields != 1 {
		return fmt.Errorf("condition must have exactly one value matching its type")
	}
	switch expr.Type {
	case "user", "group", "credential":
		value := expr.User
		if expr.Type == "group" {
			value = expr.Group
		}
		if expr.Type == "credential" {
			value = expr.Credential
		}
		if value == nil || len(value.IDs) == 0 || len(value.IDs) > 1024 {
			return fmt.Errorf("choose between 1 and 1024 identity IDs")
		}
		for _, id := range value.IDs {
			if strings.TrimSpace(id) == "" || len(id) > 128 {
				return fmt.Errorf("invalid identity ID")
			}
		}
	case "all", "any":
		children := expr.All
		if expr.Type == "any" {
			children = expr.Any
		}
		if len(children) == 0 {
			return fmt.Errorf("%s requires at least one condition", expr.Type)
		}
		for i, child := range children {
			if err := validateExpr(child, depth+1, remaining); err != nil {
				return fmt.Errorf("%s[%d]: %w", expr.Type, i, err)
			}
		}
	case "not":
		if expr.Not == nil {
			return fmt.Errorf("not requires a condition")
		}
		return validateExpr(*expr.Not, depth+1, remaining)
	case "host":
		if expr.Host == nil || strings.TrimSpace(expr.Host.List) == "" {
			return fmt.Errorf("choose a host list")
		}
	case "process":
		if expr.Process == nil || strings.TrimSpace(expr.Process.List) == "" {
			return fmt.Errorf("choose a process list")
		}
	case "inbound":
		if expr.Inbound == nil || (expr.Inbound.Name == "" && len(expr.Inbound.Names) == 0) {
			return fmt.Errorf("choose at least one inbound")
		}
		if expr.Inbound != nil {
			for _, name := range expr.Inbound.Names {
				if strings.TrimSpace(name) == "" {
					return fmt.Errorf("inbound cannot be empty")
				}
			}
		}
	case "network":
		if expr.Network == nil || (expr.Network.Network != "tcp" && expr.Network.Network != "udp") {
			return fmt.Errorf("network must be tcp or udp")
		}
	case "port":
		if expr.Port == nil {
			return fmt.Errorf("enter a port")
		}
		for part := range strings.SplitSeq(expr.Port.Ports, ",") {
			start, end, rangePort := strings.Cut(strings.TrimSpace(part), "-")
			first, err := strconv.ParseUint(start, 10, 16)
			if err != nil || first == 0 {
				return fmt.Errorf("invalid port %q", part)
			}
			if rangePort {
				last, err := strconv.ParseUint(end, 10, 16)
				if err != nil || last < first {
					return fmt.Errorf("invalid port range %q", part)
				}
			}
		}
	case "geoip":
		if expr.GeoIP == nil || strings.TrimSpace(expr.GeoIP.Countries) == "" {
			return fmt.Errorf("choose a country")
		}
		for country := range strings.SplitSeq(expr.GeoIP.Countries, ",") {
			country = strings.TrimSpace(country)
			if len(country) != 2 || country[0] < 'A' || country[0] > 'Z' || country[1] < 'A' || country[1] > 'Z' {
				return fmt.Errorf("invalid country code %q", country)
			}
		}
	default:
		return fmt.Errorf("unknown condition type %q", expr.Type)
	}
	return nil
}

// VisitListRefs visits references even inside negated or nested conditions.
func VisitListRefs(rules []RuleExpr, visit func(kind, id string) error) error {
	for _, expr := range rules {
		if expr.Host != nil {
			if err := visit("host", expr.Host.List); err != nil {
				return err
			}
		}
		if expr.Process != nil {
			if err := visit("process", expr.Process.List); err != nil {
				return err
			}
		}
		if err := VisitListRefs(expr.All, visit); err != nil {
			return err
		}
		if err := VisitListRefs(expr.Any, visit); err != nil {
			return err
		}
		if expr.Not != nil {
			if err := VisitListRefs([]RuleExpr{*expr.Not}, visit); err != nil {
				return err
			}
		}
	}
	return nil
}
