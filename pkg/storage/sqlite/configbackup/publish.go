package configbackup

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
)

// Publish removes the shared path and password and removes all targets so a
// restored publication cannot disclose nodes after its credentials are lost.
func Publish(data string) (string, bool, error) {
	value := jsontext.Value(data)
	if value.Kind() != '{' || !value.IsValid() {
		return "", false, errors.New("invalid publish configuration in export")
	}
	var document map[string]jsontext.Value
	if err := json.Unmarshal(value, &document); err != nil || document == nil {
		return "", false, errors.New("invalid publish configuration in export")
	}
	for key := range document {
		switch normalizeField(key) {
		case "password", "path":
			document[key] = jsontext.Value(`""`)
		case "points":
			document[key] = jsontext.Value(`[]`)
		}
	}
	result, err := json.Marshal(document)
	if err != nil {
		return "", false, errors.New("cannot encode redacted publish configuration")
	}
	return string(result), true, nil
}
