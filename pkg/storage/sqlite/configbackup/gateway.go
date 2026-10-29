package configbackup

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/gateway"
)

// Gateway removes header and query values that may carry credentials. A
// changed gateway and affected rules stay disabled until an administrator
// restores their policy, avoiding activation with an altered access condition.
func Gateway(data string) (string, bool, error) {
	value := jsontext.Value(data)
	if value.Kind() != '{' || !value.IsValid() {
		return "", false, errors.New("invalid gateway configuration in export")
	}
	var workspace contract.Workspace
	if err := json.Unmarshal(value, &workspace, json.RejectUnknownMembers(true)); err != nil || workspace.Version != 2 {
		return "", false, errors.New("unsupported gateway configuration in export")
	}
	changed := false
	for i := range workspace.Gateways {
		g := &workspace.Gateways[i]
		modified := redactGatewayAction(&g.Fallback)
		for j := range g.Policies {
			rule := &g.Policies[j]
			matchChanged, err := redactGatewayCondition(&rule.Match, 0)
			if err != nil {
				return "", false, err
			}
			if redactGatewayAction(&rule.Action) || matchChanged {
				rule.Enabled = false
				modified = true
			}
		}
		if modified {
			g.Enabled = false
			changed = true
		}
	}
	if !changed {
		return data, false, nil
	}
	result, err := json.Marshal(workspace)
	if err != nil {
		return "", false, errors.New("cannot encode redacted gateway configuration")
	}
	return string(result), true, nil
}

func redactGatewayAction(action *contract.Action) bool {
	changed := len(action.Rewrite.Headers) > 0 || len(action.ResponseHeaders) > 0 || action.Rewrite.Query != nil
	action.Rewrite.Headers = nil
	action.ResponseHeaders = nil
	action.Rewrite.Query = nil
	return changed
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
