// Package secret carries optional management capabilities and preserves masked
// configuration fields. It has no authentication store or forwarding hook.
package secret

import (
	"context"
	"errors"
	"reflect"
)

const Preserved = "__yuhaiin_secret_preserved_v1__"

var (
	ErrManage        = errors.New("changing a secret requires secrets:manage")
	ErrPreserved     = errors.New("a masked secret requires its existing resource")
	ErrSecurity      = errors.New("changing management security requires security:write")
	ErrExecute       = errors.New("changing executable configuration requires system:execute")
	ErrAuthorization = errors.New("configuration authorization changed")
	ErrAudit         = errors.New("durable sensitive change authorization could not be recorded")
	ErrSchema        = errors.New("unsupported secret field schema")
)

type Change struct {
	Resource string `json:"resource"`
	Secrets  bool   `json:"secrets"`
	Execute  bool   `json:"execute"`
	Security bool   `json:"security"`
}

type Capabilities struct {
	Manage, Reveal, Execute, Security bool
	Revalidate                        func(context.Context) (Capabilities, error)
	BeforeChange                      func(context.Context, Change) error
	change                            *Change
	bindReferences, resolveReferences bool
	resource                          *resourceReference
	path                              []string
}
type capabilityKey struct{}

// Absence means the optional management identity module is not installed.
func WithCapabilities(ctx context.Context, capabilities Capabilities) context.Context {
	return context.WithValue(ctx, capabilityKey{}, capabilities)
}
func FromContext(ctx context.Context) (Capabilities, bool) {
	c, ok := ctx.Value(capabilityKey{}).(Capabilities)
	return c, ok
}

// FieldPolicy supports fields whose sensitivity depends on a typed discriminator,
// such as an Authorization header matcher. Implementations return no values.
type FieldPolicy interface{ SecretField(string) bool }

// Redact clones before replacing annotated fields, so a read cannot change a
// shared live configuration. Marker strings/bytes survive ordinary JSON editors.
func Redact[T any](value T) (T, error) {
	v, err := walk(reflect.ValueOf(value), reflect.Value{}, true, Capabilities{})
	if err != nil {
		var zero T
		return zero, err
	}
	if !v.IsValid() {
		return value, nil
	}
	v, err = walk(v, reflect.ValueOf(value), true, Capabilities{bindReferences: true})
	if err != nil {
		var zero T
		return zero, err
	}
	return v.Interface().(T), nil
}

// Merge resolves markers only within the existing resource. Unmanaged callers
// retain local deployment semantics. Changes to annotated fields need explicit
// capabilities; the input and previously published value remain untouched.
func Merge[T any](ctx context.Context, next, previous T) (T, error) {
	c, managed := FromContext(ctx)
	if !managed {
		return next, nil
	}
	if c.Revalidate != nil {
		current, err := c.Revalidate(ctx)
		if err != nil {
			var zero T
			return zero, ErrAuthorization
		}
		c.Manage = c.Manage && current.Manage
		c.Execute = c.Execute && current.Execute
		c.Security = c.Security && current.Security
	}
	c.resolveReferences = true
	c.change = &Change{Resource: reflect.TypeFor[T]().String()}
	root := reflect.ValueOf(next)
	for root.IsValid() && (root.Kind() == reflect.Pointer || root.Kind() == reflect.Interface) {
		if root.IsNil() {
			break
		}
		root = root.Elem()
	}
	if root.IsValid() {
		if id, ok := stableResource(root); ok {
			c.change.Resource += ":" + id
		}
	}
	v, err := walk(reflect.ValueOf(next), reflect.ValueOf(previous), false, c)
	if err != nil {
		var zero T
		return zero, err
	}
	if !v.IsValid() {
		return next, nil
	}
	if c.BeforeChange != nil && (c.change.Secrets || c.change.Execute || c.change.Security) {
		if err := c.BeforeChange(ctx, *c.change); err != nil {
			var zero T
			return zero, ErrAudit
		}
	}
	return v.Interface().(T), nil
}
