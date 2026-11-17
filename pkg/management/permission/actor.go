package permission

import (
	"context"
	"slices"
)

type actorKey struct{}

// WithActorID lets an optional host identity middleware identify the management
// actor to shared API components without importing its authentication runtime.
// This context value grants no permission and is unrelated to traffic identities.
func WithActorID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, actorKey{}, id)
}

func ActorID(ctx context.Context) string {
	id, _ := ctx.Value(actorKey{}).(string)
	return id
}

type grantedKey struct{}

// WithGranted records the permissions of an authenticated management actor so
// shared API components can make field-level decisions without importing the
// authentication runtime. Endpoint access is still enforced by that runtime.
func WithGranted(ctx context.Context, granted []Permission) context.Context {
	return context.WithValue(ctx, grantedKey{}, slices.Clone(granted))
}

// Granted reports whether ctx carries an authenticated actor's permissions
// and, if so, whether they include p. Calls without an actor (local recovery,
// in-process callers) report authenticated=false.
func Granted(ctx context.Context, p Permission) (allowed, authenticated bool) {
	granted, ok := ctx.Value(grantedKey{}).([]Permission)
	if !ok {
		return false, false
	}
	return slices.Contains(granted, p), true
}

// Allowed reports whether ctx carries an authenticated actor holding p.
// Resource servers that do not import the identity runtime, such as the MCP
// adapter, authorize each operation with it. Without an actor nothing is
// allowed: absence never means anonymous access.
func Allowed(ctx context.Context, p Permission) bool {
	allowed, authenticated := Granted(ctx, p)
	return p != "" && authenticated && allowed
}
