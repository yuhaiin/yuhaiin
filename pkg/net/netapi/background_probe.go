package netapi

import (
	"context"
	"errors"
)

// ErrBackgroundProbeUnavailable is a local admission outcome. A periodic
// measurement cannot establish or demand a new authenticated VPN session.
var ErrBackgroundProbeUnavailable = errors.New("background probe requires an established tunnel session")

type backgroundProbeKey struct{}

// WithBackgroundProbe propagates through actual proxy chains, including Set
// and node endpoints. Ordinary/manual connections retain their existing login
// and reconnect behavior.
func WithBackgroundProbe(ctx context.Context) context.Context {
	return context.WithValue(ctx, backgroundProbeKey{}, true)
}
func IsBackgroundProbe(ctx context.Context) bool {
	value, _ := ctx.Value(backgroundProbeKey{}).(bool)
	return value
}
