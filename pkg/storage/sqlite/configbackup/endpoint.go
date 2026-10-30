package configbackup

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"net/url"
	"slices"
	"strings"

	contractinbound "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
)

var credentialFields = []string{
	"password", "salamanderpassword", "sharedsecret", "localcookie", "peercookie", "psk", "secretkey", "presharedkey", "privatekey", "privatekeybase64", "privatekeypassphrase", "clientkeypem", "tlsauthkey", "tlscryptkey", "headerprotectionkey", "authkey", "authtoken", "bearertoken", "totpsecret", "token", "credentialref", "key", "keybase64", "cakeybase64", "mldsa65seed",
}

var fieldNormalizer = strings.NewReplacer("_", "", "-", "")

// Endpoint removes recognized inline node or inbound
// credentials and disables the endpoint until its identity is restored.
// Opaque URL/path contents require separate protection.
func Endpoint(data string) (string, bool, error) {
	value := jsontext.Value(data)
	if value.Kind() != '{' || !value.IsValid() {
		return "", false, errors.New("invalid endpoint configuration in export")
	}
	var document map[string]jsontext.Value
	if err := json.Unmarshal([]byte(data), &document); err != nil || document == nil {
		return "", false, errors.New("invalid endpoint configuration in export")
	}
	changed, err := redactEndpointCredentials(document, "", 0)
	if err != nil {
		return "", false, err
	}
	if !changed {
		return data, false, nil
	}
	if _, present := document["enabled"]; present {
		document["enabled"] = jsontext.Value("false")
	}
	result, err := json.Marshal(document, json.Deterministic(true))
	if err != nil {
		return "", false, errors.New("cannot encode redacted endpoint configuration")
	}
	return string(result), true, nil
}

// Node and Inbound validate current-format documents after credential removal.
// A future field may itself contain a secret, so an older exporter must refuse
// it instead of silently placing its contents in an unencrypted backup.
func Node(data string) (string, bool, error) {
	redacted, changed, err := Endpoint(data)
	if err != nil {
		return "", false, err
	}
	var value contractnode.Node
	if err := validateEndpoint(redacted, &value); err != nil {
		return "", false, errors.New("unsupported node configuration in export")
	}
	return redacted, changed, nil
}

func Inbound(data string) (string, bool, error) {
	redacted, changed, err := Endpoint(data)
	if err != nil {
		return "", false, err
	}
	var value contractinbound.Inbound
	if err := validateEndpoint(redacted, &value); err != nil {
		return "", false, errors.New("unsupported inbound configuration in export")
	}
	return redacted, changed, nil
}

func redactEndpointCredentials(document map[string]jsontext.Value, parent string, depth int) (bool, error) {
	changed := false
	parentName := normalizeField(parent)
	for key, value := range document {
		keyName := normalizeField(key)
		arrayCredential := parentName == "authentication" && keyName == "users" ||
			parentName == "reality" && keyName == "shortids"
		if arrayCredential {
			if string(value) != "[]" && string(value) != "null" {
				document[key], changed = jsontext.Value("[]"), true
			}
			continue
		}
		if sensitiveEndpointField(parent, key) {
			if string(value) != `""` && string(value) != "null" {
				document[key], changed = jsontext.Value(`""`), true
			}
			continue
		}
		updated, childChanged, err := redactEndpointValue(value, key, depth+1)
		if err != nil {
			return false, err
		}
		if childChanged {
			document[key], changed = updated, true
		}
	}
	return changed, nil
}

func sensitiveEndpointField(parent, key string) bool {
	parent, key = normalizeField(parent), normalizeField(key)
	if slices.Contains(credentialFields, key) {
		return true
	}
	switch key {
	case "auth":
		return parent == "hysteria2"
	case "id":
		return parent == "vmess"
	case "uuid":
		return parent == "vless"
	case "shortid", "shortids":
		return parent == "reality"
	case "configyaml":
		return parent == "nebula"
	case "identity":
		return parent == "zerotier"
	case "protoparam", "obfsparam":
		// ShadowsocksR protocol parameters can contain a user key, while
		// obfuscation parameters can contain arbitrary HTTP headers.
		return parent == "shadowsocksr"
	case "data", "database64":
		// HTTP Mock payloads are arbitrary bytes and can contain credentials.
		return parent == "httpmock"
	case "username":
		return parent == "socks4a"
	default:
		return false
	}
}

func normalizeField(value string) string {
	return fieldNormalizer.Replace(strings.ToLower(value))
}

func redactEndpointValue(value jsontext.Value, parent string, depth int) (jsontext.Value, bool, error) {
	if depth > 64 {
		return nil, false, errors.New("endpoint configuration nesting exceeds export limit")
	}
	switch value.Kind() {
	case '{':
		var child map[string]jsontext.Value
		if err := json.Unmarshal(value, &child); err != nil {
			return nil, false, errors.New("invalid nested endpoint configuration")
		}
		changed, err := redactEndpointCredentials(child, parent, depth)
		if err != nil || !changed {
			return value, changed, err
		}
		encoded, err := json.Marshal(child, json.Deterministic(true))
		return encoded, true, err
	case '[':
		var items []jsontext.Value
		if err := json.Unmarshal(value, &items); err != nil {
			return nil, false, errors.New("invalid endpoint configuration array")
		}
		changed := false
		for i, item := range items {
			updated, itemChanged, err := redactEndpointValue(item, parent, depth+1)
			if err != nil {
				return nil, false, err
			}
			if itemChanged {
				items[i], changed = updated, true
			}
		}
		if !changed {
			return value, false, nil
		}
		encoded, err := json.Marshal(items)
		return encoded, true, err
	case '"':
		var text string
		if err := json.Unmarshal(value, &text); err != nil {
			return nil, false, errors.New("invalid endpoint configuration string")
		}
		if !strings.Contains(text, "://") || !strings.ContainsAny(text, "?@#") {
			return value, false, nil
		}
		u, err := url.Parse(text)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return jsontext.Value(`""`), true, nil
		}
		if u.User == nil && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" {
			return value, false, nil
		}
		u.User, u.RawQuery, u.Fragment, u.RawFragment, u.ForceQuery = nil, "", "", "", false
		encoded, err := json.Marshal(u.String())
		return encoded, true, err
	default:
		return value, false, nil
	}
}
