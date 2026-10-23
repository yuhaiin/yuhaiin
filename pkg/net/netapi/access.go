package netapi

import (
	"context"
	"errors"
	"net"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/access"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxyauth"
)

var ErrTrafficAccessDenied = &net.OpError{Op: "block", Err: errors.New("traffic access denied")}

// ErrTrafficSessionClosed is normal owner cleanup, not credential revocation.
var ErrTrafficSessionClosed = errors.New("traffic session closed")

// External is set by trusted ingress adapters, never by client headers or labels.
// It distinguishes resolver-internal forwarding from client traffic; it does not
// establish user identity, which only comes from an authenticated credential.
type TrafficSubject struct {
	Identity  *proxyauth.Identity
	InboundID string
	External  bool
}

func TrafficSubjectFromContext(ctx context.Context) TrafficSubject {
	c := GetContext(ctx)
	return TrafficSubject{Identity: TrafficIdentity(ctx), InboundID: c.GetInboundID(), External: c.GetInboundID() != "" || c.Source != nil}
}

// TrafficAccess is optional. Protected scopes authenticate before resolution and
// authorize the original name together with the exact, pinned dial destination.
type TrafficAccess interface {
	Managed(TrafficSubject) bool
	Preflight(TrafficSubject) error
	Decide(TrafficSubject, Address, Address) contract.Decision
	NewSession(TrafficSubject, func(error)) (TrafficAccessSession, error)
}

type TrafficAccessSession interface {
	Authorize(original Address, resolved net.Addr) error
	Close()
}

type policyOriginalKey struct{}

func PolicyOriginalDestination(ctx context.Context) Address {
	address, _ := ctx.Value(policyOriginalKey{}).(Address)
	return address
}

// PolicyContext is reusable by a compiled policy evaluator. It carries only
// authenticated subject metadata, without allocating context values per packet.
type PolicyContext struct {
	*Context
	Subject  TrafficSubject
	Original Address
}

func NewPolicyContext() *PolicyContext {
	return &PolicyContext{Context: WithContext(context.Background())}
}

func (c *PolicyContext) SetSubject(subject TrafficSubject) {
	c.Subject = subject
	c.inboundID = &c.Subject.InboundID
}

func (c *PolicyContext) Value(key any) any {
	switch key {
	case identityKey{}:
		return c.Subject.Identity
	case policyOriginalKey{}:
		return c.Original
	default:
		return c.Context.Value(key)
	}
}
