package secret

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/v2"
	"reflect"
	"slices"
	"strconv"
	"strings"
)

// References contain an opaque keyed revision and a signed source path.
// The revision is not a public hash of a password or private configuration.
// They bind opaque preservation to one resource and permit authorized reordering
// without accidentally attaching another protocol layer's password/private key.
// Restarting the process deliberately invalidates outstanding editor references.
var referenceKey = func() [32]byte { var key [32]byte; _, _ = rand.Read(key[:]); return key }()

type reference struct {
	Resource string   `json:"r"`
	Snapshot string   `json:"s"`
	Path     []string `json:"p"`
}
type resourceReference struct {
	resource, snapshot string
	previous           reflect.Value
	source             reflect.Value
}
type resourceIdentity interface{ SecretResourceID() string }

func stableResource(value reflect.Value) (string, bool) {
	if value.Kind() != reflect.Struct {
		return "", false
	}
	if named, ok := value.Interface().(resourceIdentity); ok {
		return named.SecretResourceID(), true
	}
	if id := value.FieldByName("ID"); id.IsValid() && id.Kind() == reflect.String {
		return id.String(), true
	}
	return "", false
}

func enterResource(next, old reflect.Value, c Capabilities) (Capabilities, error) {
	if !c.bindReferences && !c.resolveReferences || next.Kind() != reflect.Struct {
		return c, nil
	}
	id, boundary := stableResource(next)
	if c.resource != nil && !boundary {
		return c, nil
	}
	current := old
	c.resource = &resourceReference{resource: next.Type().PkgPath() + "/" + next.Type().String() + ":" + id, previous: old, source: current}
	c.path = nil
	return c, nil
}

func childPath(c Capabilities, part string) Capabilities {
	if c.bindReferences || c.resolveReferences {
		c.path = append(slices.Clone(c.path), part)
	}
	return c
}

func signedMarker(c Capabilities) (string, error) {
	if c.resource == nil {
		return "", ErrSchema
	}
	snapshot, err := referenceSnapshot(c.resource)
	if err != nil {
		return "", err
	}
	encoded, err := json.Marshal(reference{Resource: c.resource.resource, Snapshot: snapshot, Path: c.path})
	if err != nil {
		return "", err
	}
	payload := base64.RawURLEncoding.EncodeToString(encoded)
	mac := hmac.New(sha256.New, referenceKey[:])
	_, _ = mac.Write([]byte("secret-reference\x00"))
	_, _ = mac.Write([]byte(payload))
	return Preserved + "." + payload + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func markerText(value reflect.Value) (string, bool) {
	for value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return "", false
		}
		value = value.Elem()
	}
	var text string
	switch value.Kind() {
	case reflect.String:
		text = value.String()
	case reflect.Slice:
		if value.Type().Elem().Kind() == reflect.Uint8 {
			text = string(value.Bytes())
		} else if value.Type().Elem().Kind() == reflect.String && value.Len() == 1 {
			text = value.Index(0).String()
		}
	}
	return text, text == Preserved || strings.HasPrefix(text, Preserved+".")
}

func resolveMarker(next, old reflect.Value, c Capabilities) (reflect.Value, error) {
	text, _ := markerText(next)
	if text == Preserved {
		if old.IsZero() || (old.Kind() == reflect.Slice || old.Kind() == reflect.Map) && old.Len() == 0 {
			return reflect.Value{}, ErrPreserved
		}
		return walk(old, reflect.Value{}, false, Capabilities{Manage: true, Execute: true})
	}
	if len(text) > 16384 || c.resource == nil {
		return reflect.Value{}, ErrPreserved
	}
	payload, signature, ok := strings.CutLast(strings.TrimPrefix(text, Preserved+"."), ".")
	if !ok {
		return reflect.Value{}, ErrPreserved
	}
	provided, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return reflect.Value{}, ErrPreserved
	}
	mac := hmac.New(sha256.New, referenceKey[:])
	_, _ = mac.Write([]byte("secret-reference\x00"))
	_, _ = mac.Write([]byte(payload))
	if !hmac.Equal(provided, mac.Sum(nil)) {
		return reflect.Value{}, ErrPreserved
	}
	encoded, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return reflect.Value{}, ErrPreserved
	}
	var r reference
	snapshot, snapshotErr := referenceSnapshot(c.resource)
	if snapshotErr != nil || json.Unmarshal(encoded, &r, json.RejectUnknownMembers(true)) != nil || len(r.Path) > 256 || r.Resource != c.resource.resource || r.Snapshot != snapshot {
		return reflect.Value{}, ErrPreserved
	}
	if !c.Manage && !slices.Equal(r.Path, c.path) {
		return reflect.Value{}, ErrManage
	}
	value := c.resource.previous
	for _, part := range r.Path {
		for value.Kind() == reflect.Pointer || value.Kind() == reflect.Interface {
			if value.IsNil() {
				return reflect.Value{}, ErrPreserved
			}
			value = value.Elem()
		}
		switch value.Kind() {
		case reflect.Struct:
			field, ok := value.Type().FieldByName(part)
			if !ok || !field.IsExported() {
				return reflect.Value{}, ErrPreserved
			}
			value = value.FieldByIndex(field.Index)
		case reflect.Slice, reflect.Array:
			i, err := strconv.Atoi(part)
			if err != nil || i < 0 || i >= value.Len() {
				return reflect.Value{}, ErrPreserved
			}
			value = value.Index(i)
		case reflect.Map:
			if value.Type().Key().Kind() != reflect.String {
				return reflect.Value{}, ErrPreserved
			}
			key := reflect.New(value.Type().Key()).Elem()
			key.SetString(part)
			value = value.MapIndex(key)
			if !value.IsValid() {
				return reflect.Value{}, ErrPreserved
			}
		default:
			return reflect.Value{}, ErrPreserved
		}
	}
	if value.Type() != next.Type() || value.IsZero() {
		return reflect.Value{}, ErrPreserved
	}
	return walk(value, reflect.Value{}, false, Capabilities{Manage: true, Execute: true})
}

func referenceSnapshot(r *resourceReference) (string, error) {
	if r.snapshot != "" {
		return r.snapshot, nil
	}
	encoded, err := json.Marshal(r.source.Interface(), json.Deterministic(true))
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, referenceKey[:])
	_, _ = mac.Write([]byte("secret-snapshot\x00"))
	_, _ = mac.Write(encoded)
	r.snapshot = base64.RawURLEncoding.EncodeToString(mac.Sum(nil)[:16])
	return r.snapshot, nil
}
