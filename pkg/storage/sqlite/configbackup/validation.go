package configbackup

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"slices"
	"strconv"
)

// Validation decodes against the current schema and returns the document that
// may be exported. Old documents can contain a known credential alias outside
// the current schema; Endpoint has already cleared its value, so those empty
// aliases are removed silently. Any other unrecognized member (a removed
// protocol, a field from a newer version) is dropped from the export: it may
// hold a secret this exporter cannot recognize, and the current version cannot
// use it anyway. pruned reports that such content was discarded.
func validateEndpoint(data string, target any) (jsontext.Value, bool, error) {
	value := jsontext.Value(data)
	pruned := false
	for attempt := 0; ; attempt++ {
		err := json.Unmarshal(value, target, json.RejectUnknownMembers(true), json.MatchCaseInsensitiveNames(true))
		if err == nil {
			return value, pruned, nil
		}
		semantic, ok := errors.AsType[*json.SemanticError](err)
		if !ok || !errors.Is(semantic.Err, json.ErrUnknownName) {
			return nil, false, err
		}
		if attempt == 1024 {
			return nil, false, errors.New("too many unrecognized members in export")
		}
		tokens := slices.Collect(semantic.JSONPointer.Tokens())
		var updated jsontext.Value
		removed := false
		if len(tokens) >= 2 && sensitiveEndpointField(tokens[len(tokens)-2], tokens[len(tokens)-1]) {
			updated, removed = removeValidationMember(value, tokens, true)
		}
		if !removed {
			if updated, removed = removeValidationMember(value, tokens, false); !removed {
				return nil, false, err
			}
			pruned = true
		}
		value = updated
	}
}

func removeValidationMember(value jsontext.Value, path []string, emptyOnly bool) (jsontext.Value, bool) {
	if len(path) == 0 {
		return nil, false
	}
	switch value.Kind() {
	case '{':
		var object map[string]jsontext.Value
		if json.Unmarshal(value, &object) != nil {
			return nil, false
		}
		child, exists := object[path[0]]
		if !exists {
			return nil, false
		}
		if len(path) == 1 {
			if emptyOnly && string(child) != `""` && string(child) != "null" && string(child) != "[]" {
				return nil, false
			}
			delete(object, path[0])
		} else {
			updated, removed := removeValidationMember(child, path[1:], emptyOnly)
			if !removed {
				return nil, false
			}
			object[path[0]] = updated
		}
		encoded, err := json.Marshal(object, json.Deterministic(true))
		return encoded, err == nil
	case '[':
		var items []jsontext.Value
		index, err := strconv.Atoi(path[0])
		if err != nil || json.Unmarshal(value, &items) != nil || index < 0 || index >= len(items) {
			return nil, false
		}
		updated, removed := removeValidationMember(items[index], path[1:], emptyOnly)
		if !removed {
			return nil, false
		}
		items[index] = updated
		encoded, err := json.Marshal(items)
		return encoded, err == nil
	default:
		return nil, false
	}
}
