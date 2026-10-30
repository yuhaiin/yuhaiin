package configbackup

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"slices"
	"strconv"
)

// Validation operates on a private copy. Old documents can contain a known
// credential alias outside the current schema; Endpoint has already cleared
// its value. Ignore only those empty aliases while still rejecting every other
// unrecognized member, including unknown siblings and descendants.
func validateEndpoint(data string, target any) error {
	value := jsontext.Value(data)
	for attempt := 0; ; attempt++ {
		err := json.Unmarshal(value, target, json.RejectUnknownMembers(true), json.MatchCaseInsensitiveNames(true))
		if err == nil {
			return nil
		}
		semantic, ok := errors.AsType[*json.SemanticError](err)
		if !ok || !errors.Is(semantic.Err, json.ErrUnknownName) {
			return err
		}
		if attempt == 128 {
			return errors.New("too many legacy credential aliases in export")
		}
		tokens := slices.Collect(semantic.JSONPointer.Tokens())
		if len(tokens) < 2 || !sensitiveEndpointField(tokens[len(tokens)-2], tokens[len(tokens)-1]) {
			return err
		}
		var removed bool
		value, removed = removeEmptyValidationMember(value, tokens)
		if !removed {
			return err
		}
	}
}

func removeEmptyValidationMember(value jsontext.Value, path []string) (jsontext.Value, bool) {
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
			if string(child) != `""` && string(child) != "null" {
				return nil, false
			}
			delete(object, path[0])
		} else {
			updated, removed := removeEmptyValidationMember(child, path[1:])
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
		updated, removed := removeEmptyValidationMember(items[index], path[1:])
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
