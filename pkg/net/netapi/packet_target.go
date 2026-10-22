package netapi

import "context"

type packetTargetKey struct{}

// WithPacketTarget carries a negotiated relay endpoint through transparent
// transports to the nearest fixed endpoint layer. It applies to one dial only.
func WithPacketTarget(ctx context.Context, target Address) context.Context {
	return context.WithValue(ctx, packetTargetKey{}, target)
}

// ConsumePacketTarget prevents an override from reaching lower endpoint layers
// when this layer dials its own parent proxy.
func ConsumePacketTarget(ctx context.Context) (context.Context, Address) {
	target, _ := ctx.Value(packetTargetKey{}).(Address)
	if target == nil {
		return ctx, nil
	}
	return context.WithValue(ctx, packetTargetKey{}, nil), target
}
