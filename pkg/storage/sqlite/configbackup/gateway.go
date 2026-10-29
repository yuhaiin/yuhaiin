package configbackup

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"net/url"
	"strings"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/gateway"
)

// Gateway removes header and query values that may carry credentials. A
// changed gateway and affected rules stay disabled until an administrator
// restores their policy, avoiding activation with an altered access condition.
func Gateway(data string) (string, bool, bool, error) {
	value := jsontext.Value(data)
	if value.Kind() != '{' || !value.IsValid() {
		return "", false, false, errors.New("invalid gateway configuration in export")
	}
	var workspace contract.Workspace
	if err := json.Unmarshal(value, &workspace, json.RejectUnknownMembers(true)); err != nil || workspace.Version != 2 {
		return "", false, false, errors.New("unsupported gateway configuration in export")
	}
	changed, guarded := false, false
	for i := range workspace.Gateways {
		g := &workspace.Gateways[i]
		modified, err := redactGatewayAction(&g.Fallback)
		if err != nil {
			return "", false, false, err
		}
		for j := range g.Policies {
			rule := &g.Policies[j]
			matchChanged, err := redactGatewayCondition(&rule.Match, 0)
			if err != nil {
				return "", false, false, err
			}
			actionChanged, err := redactGatewayAction(&rule.Action)
			if err != nil {
				return "", false, false, err
			}
			if actionChanged || matchChanged {
				rule.Enabled = false
				modified = true
			}
		}
		for j := range g.BackendPools {
			pool := &g.BackendPools[j]
			var scrubbed bool
			pool.HealthPath, scrubbed, err = redactGatewayURL(pool.HealthPath)
			if err != nil {
				return "", false, false, err
			}
			modified = modified || scrubbed
			for k := range pool.Backends {
				pool.Backends[k].URL, scrubbed, err = redactGatewayURL(pool.Backends[k].URL)
				if err != nil {
					return "", false, false, err
				}
				modified = modified || scrubbed
			}
		}
		for j := range g.Filters {
			filter := &g.Filters[j]
			var scrubbed bool
			filter.URL, scrubbed, err = redactGatewayURL(filter.URL)
			if err != nil {
				return "", false, false, err
			}
			if scrubbed {
				filter.Enabled, modified = false, true
			}
		}
		if modified {
			g.Enabled = false
			g.RejectWhenDisabled = true
			changed = true
		}
		guarded = guarded || g.RejectWhenDisabled
	}
	if !changed {
		return data, false, guarded, nil
	}
	result, err := json.Marshal(workspace)
	if err != nil {
		return "", false, false, errors.New("cannot encode redacted gateway configuration")
	}
	return string(result), true, guarded, nil
}

func redactGatewayAction(action *contract.Action) (bool, error) {
	changed := len(action.Rewrite.Headers) > 0 || len(action.ResponseHeaders) > 0 || action.Rewrite.Query != nil
	action.Rewrite.Headers = nil
	action.ResponseHeaders = nil
	action.Rewrite.Query = nil
	var locationChanged bool
	var err error
	action.Location, locationChanged, err = redactGatewayURL(action.Location)
	if locationChanged && action.Location == "" && action.Type == "redirect" {
		// A query-only relative redirect becomes empty after redaction. Keep a
		// valid inert placeholder so the disabled policy remains editable.
		action.Location = "/"
	}
	return changed || locationChanged, err
}

// URL paths may themselves be bearer credentials and remain an explicit
// limitation of unencrypted configuration exports.
func redactGatewayURL(raw string) (string, bool, error) {
	if !strings.ContainsAny(raw, "?@#") {
		return raw, false, nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", false, errors.New("invalid gateway URL in configuration export")
	}
	if u.User == nil && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" {
		return raw, false, nil
	}
	u.User, u.RawQuery, u.Fragment, u.RawFragment, u.ForceQuery = nil, "", "", "", false
	return u.String(), true, nil
}

func redactGatewayCondition(condition *contract.Condition, depth int) (bool, error) {
	if depth > 16 {
		return false, errors.New("gateway condition nesting exceeds export limit")
	}
	changed := false
	if (condition.Field == "header" || condition.Field == "query") && (len(condition.Values) > 0 || condition.Value != "") {
		condition.Values = []string{"redacted"}
		condition.Value = ""
		changed = true
	}
	for i := range condition.All {
		child, err := redactGatewayCondition(&condition.All[i], depth+1)
		if err != nil {
			return false, err
		}
		changed = changed || child
	}
	for i := range condition.Any {
		child, err := redactGatewayCondition(&condition.Any[i], depth+1)
		if err != nil {
			return false, err
		}
		changed = changed || child
	}
	if condition.Not != nil {
		child, err := redactGatewayCondition(condition.Not, depth+1)
		if err != nil {
			return false, err
		}
		changed = changed || child
	}
	return changed, nil
}
