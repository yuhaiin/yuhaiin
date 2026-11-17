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

// WithGranted records the permissions an authenticated management principal
// holds for this request. Resource servers that do not import the identity
// runtime, such as the MCP adapter, authorize individual operations with
// Allowed. Absence means no permission at all, never anonymous access.
func WithGranted(ctx context.Context, permissions []Permission) context.Context {
	return context.WithValue(ctx, grantedKey{}, slices.Clone(permissions))
}

// Granted returns the permissions recorded by WithGranted.
func Granted(ctx context.Context) ([]Permission, bool) {
	permissions, ok := ctx.Value(grantedKey{}).([]Permission)
	return slices.Clone(permissions), ok
}

// Allowed reports whether the request principal holds p.
func Allowed(ctx context.Context, p Permission) bool {
	permissions, _ := ctx.Value(grantedKey{}).([]Permission)
	return p != "" && slices.Contains(permissions, p)
}
