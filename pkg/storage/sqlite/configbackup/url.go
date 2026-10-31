package configbackup

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"net/url"
	"strings"
)

var ErrPrivateSourceURL = errors.New("configuration source URL may contain credentials; use an encrypted full recovery backup")

// SourceURL refuses components that can carry credentials. Removing them would
// change the resource and can silently weaken a routing or DNS policy.
// Opaque path segments still require protection by the operator.
func SourceURL(raw string) error {
	if !strings.ContainsAny(raw, "?@#") {
		return nil
	}
	parsed := raw
	if strings.HasPrefix(parsed, "//") {
		parsed = "https:" + parsed
	} else if !strings.Contains(parsed, "://") {
		// DoH accepts an authority without a scheme and adds HTTPS itself.
		parsed = "https://" + parsed
	}
	u, err := url.Parse(parsed)
	if err != nil {
		return errors.New("invalid source URL in configuration backup")
	}
	if u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return ErrPrivateSourceURL
	}
	return nil
}

func SourceDocument(data string) error {
	value := jsontext.Value(data)
	if !value.IsValid() {
		return errors.New("invalid source document in configuration backup")
	}
	return sourceValue(value, "", 0)
}

func sourceValue(value jsontext.Value, field string, depth int) error {
	if depth > 64 {
		return errors.New("source configuration nesting exceeds backup limit")
	}
	switch value.Kind() {
	case '{':
		var object map[string]jsontext.Value
		if json.Unmarshal(value, &object) != nil {
			return errors.New("invalid source object in configuration backup")
		}
		for key, child := range object {
			if err := sourceValue(child, key, depth+1); err != nil {
				return err
			}
		}
	case '[':
		var items []jsontext.Value
		if json.Unmarshal(value, &items) != nil {
			return errors.New("invalid source list in configuration backup")
		}
		for _, child := range items {
			if err := sourceValue(child, field, depth+1); err != nil {
				return err
			}
		}
	case '"':
		var text string
		if json.Unmarshal(value, &text) != nil {
			return errors.New("invalid source string in configuration backup")
		}
		key := normalizeField(field)
		if strings.Contains(text, "://") || key == "url" || key == "urls" || key == "downloadurl" || key == "host" {
			return SourceURL(text)
		}
	}
	return nil
}
