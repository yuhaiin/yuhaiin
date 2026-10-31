package permission

import "context"

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
