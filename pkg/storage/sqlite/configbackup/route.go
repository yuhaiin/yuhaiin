package configbackup

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
)

// RouteRefreshErrors are transient and may contain full credential-bearing
// download URLs. Keep the actual source and refresh configuration untouched.
func RouteRefreshErrors(data, field string) (string, bool, error) {
	value := jsontext.Value(data)
	if value.Kind() != '{' || !value.IsValid() {
		return "", false, errors.New("invalid route refresh configuration in export")
	}
	var document map[string]jsontext.Value
	if err := json.Unmarshal(value, &document); err != nil || document == nil {
		return "", false, errors.New("invalid route refresh configuration in export")
	}
	if _, ok := document[field]; !ok {
		return data, false, nil
	}
	delete(document, field)
	result, err := json.Marshal(document, json.Deterministic(true))
	if err != nil {
		return "", false, errors.New("cannot encode route refresh configuration")
	}
	return string(result), true, nil
}
