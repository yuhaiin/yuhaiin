// Package access defines traffic authorization independently of route selection.
package access

import route "github.com/Asutorufa/yuhaiin/pkg/contract/route"

type Scope struct {
	AllInbounds bool     `json:"allInbounds"`
	Inbounds    []string `json:"inbounds"`
}

type Rule struct {
	ID         string           `json:"id"`
	Name       string           `json:"name"`
	Action     string           `json:"action"`
	Disabled   bool             `json:"disabled"`
	Conditions []route.RuleExpr `json:"conditions"`
}

// Rules are first-match, in array order. DefaultAction is explicit when enabled.
type Config struct {
	Revision      uint64 `json:"revision"`
	Enabled       bool   `json:"enabled"`
	Scope         Scope  `json:"scope"`
	DefaultAction string `json:"defaultAction"`
	Rules         []Rule `json:"rules"`
}

type Decision struct {
	Revision uint64 `json:"revision"`
	Managed  bool   `json:"managed"`
	Allowed  bool   `json:"allowed"`
	RuleID   string `json:"ruleId"`
	Reason   string `json:"reason"`
}

type Status struct {
	Revision         uint64 `json:"revision"`
	Sessions         int    `json:"sessions"`
	Denied           string `json:"denied"`
	Revoked          string `json:"revoked"`
	CapacityRejected string `json:"capacityRejected"`
}
