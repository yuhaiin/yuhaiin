package secret

import (
	"reflect"
	"sync"
)

var (
	fieldPolicyType = reflect.TypeFor[FieldPolicy]()
	redactableTypes sync.Map // reflect.Type -> bool
)

// mayHoldSecret reports whether walk could change a value of type t during
// redaction. It is a static, conservative check: interfaces, FieldPolicy
// implementations and `secret` tags all count, so a false result means Redact
// would return an equal copy and can skip the reflective deep copy entirely.
func mayHoldSecret(t reflect.Type) bool {
	if t == nil {
		return false
	}
	if v, ok := redactableTypes.Load(t); ok {
		return v.(bool)
	}
	result := typeMayHoldSecret(t, make(map[reflect.Type]bool))
	redactableTypes.Store(t, result)
	return result
}

// Only the top-level result is cached: a nested type evaluated while one of
// its ancestors is still in progress may be missing that ancestor's secrets.
func typeMayHoldSecret(t reflect.Type, visiting map[reflect.Type]bool) bool {
	if visiting[t] {
		return false
	}
	visiting[t] = true
	defer delete(visiting, t)
	switch t.Kind() {
	case reflect.Interface:
		return true
	case reflect.Pointer, reflect.Slice, reflect.Array, reflect.Map:
		return typeMayHoldSecret(t.Elem(), visiting)
	case reflect.Struct:
		if t.Implements(fieldPolicyType) || reflect.PointerTo(t).Implements(fieldPolicyType) {
			return true
		}
		for field := range t.Fields() {
			if !field.IsExported() {
				continue
			}
			if _, ok := field.Tag.Lookup("secret"); ok {
				return true
			}
			if typeMayHoldSecret(field.Type, visiting) {
				return true
			}
		}
	}
	return false
}
