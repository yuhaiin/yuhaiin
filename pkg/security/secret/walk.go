package secret

import (
	"net/url"
	"reflect"
	"strconv"
	"strings"
)

func oldValue(old reflect.Value, t reflect.Type) reflect.Value {
	if old.IsValid() && old.Type() == t {
		return old
	}
	return reflect.Zero(t)
}

func walk(next, old reflect.Value, redact bool, c Capabilities) (reflect.Value, error) {
	if !next.IsValid() {
		return next, nil
	}
	old = oldValue(old, next.Type())
	var enterErr error
	c, enterErr = enterResource(next, old, c)
	if enterErr != nil {
		return reflect.Value{}, enterErr
	}
	switch next.Kind() {
	case reflect.Pointer:
		if next.IsNil() {
			if !redact && !old.IsNil() {
				if _, err := walk(reflect.Zero(next.Type().Elem()), old.Elem(), false, c); err != nil {
					return reflect.Value{}, err
				}
			}
			return reflect.Zero(next.Type()), nil
		}
		var prior reflect.Value
		if !old.IsNil() {
			prior = old.Elem()
		}
		v, err := walk(next.Elem(), prior, redact, c)
		if err != nil {
			return reflect.Value{}, err
		}
		out := reflect.New(next.Type().Elem())
		out.Elem().Set(v)
		return out, nil
	case reflect.Interface:
		if next.IsNil() {
			return reflect.Zero(next.Type()), nil
		}
		var prior reflect.Value
		if !old.IsNil() {
			prior = old.Elem()
		}
		v, err := walk(next.Elem(), prior, redact, c)
		if err != nil {
			return reflect.Value{}, err
		}
		out := reflect.New(next.Type()).Elem()
		out.Set(v)
		return out, nil
	case reflect.Struct:
		out := reflect.New(next.Type()).Elem()
		out.Set(next)
		policy, _ := next.Interface().(FieldPolicy)
		priorPolicy, _ := old.Interface().(FieldPolicy)
		for i := range next.NumField() {
			field := next.Type().Field(i)
			if !field.IsExported() {
				continue
			}
			mode := field.Tag.Get("secret")
			sensitive := policy != nil && policy.SecretField(field.Name)
			previousSensitive := priorPolicy != nil && priorPolicy.SecretField(field.Name)
			if sensitive || previousSensitive {
				mode = "true"
			}
			if !redact && previousSensitive && !sensitive && !old.Field(i).IsZero() {
				if isMarker(next.Field(i)) {
					return reflect.Value{}, ErrPreserved
				}
				if !c.Manage {
					return reflect.Value{}, ErrManage
				}
			}

			var v reflect.Value
			var err error
			if mode != "" {
				v, err = secretField(next.Field(i), old.Field(i), mode, redact, childPath(c, field.Name))
			} else {
				v, err = walk(next.Field(i), old.Field(i), redact, childPath(c, field.Name))
			}
			if err != nil {
				return reflect.Value{}, err
			}
			if !redact && field.Tag.Get("privilege") == "secrets:manage" && !c.Manage && !reflect.DeepEqual(v.Interface(), old.Field(i).Interface()) {
				return reflect.Value{}, ErrManage
			}
			if !redact && field.Tag.Get("privilege") == "system:execute" && !c.Execute && !reflect.DeepEqual(v.Interface(), old.Field(i).Interface()) {
				return reflect.Value{}, ErrExecute
			}
			if !redact && field.Tag.Get("privilege") == "security:write" && !c.Security && !reflect.DeepEqual(v.Interface(), old.Field(i).Interface()) {
				return reflect.Value{}, ErrSecurity
			}
			if !redact && c.change != nil && !reflect.DeepEqual(v.Interface(), old.Field(i).Interface()) {
				if field.Tag.Get("privilege") == "system:execute" {
					c.change.Execute = true
				}
				if field.Tag.Get("privilege") == "security:write" {
					c.change.Security = true
				}
				if field.Tag.Get("privilege") == "secrets:manage" {
					c.change.Secrets = true
				}
			}
			out.Field(i).Set(v)
		}
		return out, nil
	case reflect.Slice, reflect.Array:
		var out reflect.Value
		if next.Kind() == reflect.Slice {
			if next.IsNil() {
				out = reflect.Zero(next.Type())
			} else {
				out = reflect.MakeSlice(next.Type(), next.Len(), next.Len())
			}
		} else {
			out = reflect.New(next.Type()).Elem()
		}
		used := make([]bool, old.Len())
		for i := range next.Len() {
			prior := reflect.Value{}
			index := i
			if id := resourceKey(next.Index(i)); id != "" {
				index = -1
				for j := range old.Len() {
					if !used[j] && resourceKey(old.Index(j)) == id {
						index = j
						break
					}
				}
			}
			if index >= 0 && index < old.Len() {
				prior = old.Index(index)
				used[index] = true
			}
			v, err := walk(next.Index(i), prior, redact, childPath(c, strconv.Itoa(i)))
			if err != nil {
				return reflect.Value{}, err
			}
			out.Index(i).Set(v)
		}
		if !redact {
			for i := range old.Len() {
				if !used[i] {
					if _, err := walk(reflect.Zero(old.Type().Elem()), old.Index(i), false, childPath(c, strconv.Itoa(i))); err != nil {
						return reflect.Value{}, err
					}
				}
			}
		}
		return out, nil
	case reflect.Map:
		out := reflect.Zero(next.Type())
		if !next.IsNil() {
			out = reflect.MakeMapWithSize(next.Type(), next.Len())
		}
		for _, key := range next.MapKeys() {
			v, err := walk(next.MapIndex(key), old.MapIndex(key), redact, childPath(c, key.String()))
			if err != nil {
				return reflect.Value{}, err
			}
			out.SetMapIndex(key, v)
		}
		if !redact {
			for _, key := range old.MapKeys() {
				if !next.MapIndex(key).IsValid() {
					if _, err := walk(reflect.Zero(old.Type().Elem()), old.MapIndex(key), false, childPath(c, key.String())); err != nil {
						return reflect.Value{}, err
					}
				}
			}
		}
		return out, nil
	default:
		return next, nil
	}
}

// Match repeated objects by stable ID/name/public key, never another resource's
// array position. Discriminated protocol layers also retain their type.
func resourceKey(value reflect.Value) string {
	for value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return ""
		}
		value = value.Elem()
	}
	if value.Kind() != reflect.Struct {
		return ""
	}
	for _, name := range []string{"ID", "Name", "PublicKey"} {
		if field := value.FieldByName(name); field.IsValid() && field.Kind() == reflect.String && field.String() != "" {
			return name + ":" + field.String()
		}
	}
	if field := value.FieldByName("Type"); field.IsValid() && field.Kind() == reflect.String {
		return "type:" + field.String()
	}
	return ""
}

func secretField(next, old reflect.Value, mode string, redact bool, c Capabilities) (result reflect.Value, err error) {
	old = oldValue(old, next.Type())
	defer func() {
		if redact || c.change == nil || err != nil || !result.IsValid() || reflect.DeepEqual(result.Interface(), old.Interface()) {
			return
		}
		if (mode == "url" || mode == "urls") && !sensitiveURLValue(result) && !sensitiveURLValue(old) {
			return
		}
		c.change.Secrets = true
	}()
	if !redact && isMarker(next) {
		resolved, err := resolveMarker(next, old, c)
		if err == nil && c.change != nil && !reflect.DeepEqual(resolved.Interface(), old.Interface()) {
			c.change.Secrets = true
		}
		return resolved, err
	}
	if mode == "urls" {
		out := reflect.MakeSlice(next.Type(), next.Len(), next.Len())
		for i := range next.Len() {
			prior := reflect.Value{}
			if i < old.Len() {
				prior = old.Index(i)
			}
			v, err := secretField(next.Index(i), oldValue(prior, next.Type().Elem()), "url", redact, childPath(c, strconv.Itoa(i)))
			if err != nil {
				return reflect.Value{}, err
			}
			out.Index(i).Set(v)
		}
		if !redact && !c.Manage {
			for i := next.Len(); i < old.Len(); i++ {
				if secretURL(old.Index(i).String()) {
					return reflect.Value{}, ErrManage
				}
			}
		}
		if next.IsNil() {
			return reflect.Zero(next.Type()), nil
		}
		return out, nil
	}
	if mode == "values" {
		return secretValues(next, old, redact, c)
	}

	if next.Kind() == reflect.Pointer {
		if next.IsNil() {
			if !redact && !old.IsNil() && !c.Manage {
				return reflect.Value{}, ErrManage
			}
			return reflect.Zero(next.Type()), nil
		}
		var prior reflect.Value
		if !old.IsNil() {
			prior = old.Elem()
		}
		v, err := secretField(next.Elem(), prior, mode, redact, c)
		if err != nil {
			return reflect.Value{}, err
		}
		out := reflect.New(next.Type().Elem())
		out.Elem().Set(v)
		return out, nil
	}
	if mode == "url" && !secretURL(next.String()) && !secretURL(old.String()) && !isMarker(next) {
		return next, nil
	}
	if redact {
		if next.IsZero() || (next.Kind() == reflect.Slice || next.Kind() == reflect.Map) && next.Len() == 0 {
			return next, nil
		}
		return marker(next, c)
	}
	if !c.Manage && (!reflect.DeepEqual(next.Interface(), old.Interface()) || !emptySecret(next) && !c.existingPlaintext) {
		return reflect.Value{}, ErrManage
	}
	if c.change != nil && !reflect.DeepEqual(next.Interface(), old.Interface()) {
		c.change.Secrets = true
	}
	return walk(next, reflect.Value{}, false, Capabilities{Manage: true, Execute: true, Security: true})
}

func marker(value reflect.Value, c Capabilities) (reflect.Value, error) {
	text := Preserved
	if c.bindReferences {
		var err error
		text, err = signedMarker(c)
		if err != nil {
			return reflect.Value{}, err
		}
	}
	out := reflect.New(value.Type()).Elem()
	switch value.Kind() {
	case reflect.String:
		out.SetString(text)
	case reflect.Slice:
		if value.Type().Elem().Kind() == reflect.Uint8 {
			out.SetBytes([]byte(text))
		} else if value.Type().Elem().Kind() == reflect.String {
			out = reflect.MakeSlice(value.Type(), 1, 1)
			out.Index(0).SetString(text)
		} else {
			return reflect.Value{}, ErrSchema
		}
	default:
		return reflect.Value{}, ErrSchema
	}
	return out, nil
}

func isMarker(value reflect.Value) bool { _, ok := markerText(value); return ok }

func secretValues(next, old reflect.Value, redact bool, c Capabilities) (reflect.Value, error) {
	if next.Kind() != reflect.Map {
		return reflect.Value{}, ErrSchema
	}
	out := reflect.Zero(next.Type())
	if !next.IsNil() {
		out = reflect.MakeMapWithSize(next.Type(), next.Len())
	}
	for _, key := range next.MapKeys() {
		v, err := secretField(next.MapIndex(key), old.MapIndex(key), "true", redact, childPath(c, key.String()))
		if err != nil {
			return reflect.Value{}, err
		}
		out.SetMapIndex(key, v)
	}
	if !redact && !c.Manage {
		for _, key := range old.MapKeys() {
			if !next.MapIndex(key).IsValid() && !old.MapIndex(key).IsZero() {
				return reflect.Value{}, ErrManage
			}
		}
	}
	return out, nil
}

func secretURL(value string) bool {
	u, err := url.Parse(value)
	if err != nil {
		return strings.ContainsAny(value, "?@#") || strings.Contains(value, "://")
	}
	return u.User != nil || u.RawQuery != "" || u.Fragment != ""
}

func sensitiveURLValue(value reflect.Value) bool {
	for value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return false
		}
		value = value.Elem()
	}
	if value.Kind() == reflect.String {
		return secretURL(value.String())
	}
	if value.Kind() == reflect.Slice {
		for i := range value.Len() {
			if sensitiveURLValue(value.Index(i)) {
				return true
			}
		}
	}
	return false
}

func emptySecret(value reflect.Value) bool {
	return value.IsZero() || (value.Kind() == reflect.Slice || value.Kind() == reflect.Map) && value.Len() == 0
}
