package netapi

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/access"
)

type trafficAuthorizationKey struct{}

type TrafficAuthorization struct {
	Session  TrafficAccessSession
	Context  context.Context
	Decision *contract.Decision
}

func WithTrafficAuthorization(ctx context.Context, s TrafficAccessSession, lifetime context.Context) context.Context {
	return context.WithValue(ctx, trafficAuthorizationKey{}, &TrafficAuthorization{Session: s, Context: lifetime})
}
func TrafficAuthorizationFromContext(ctx context.Context) *TrafficAuthorization {
	state, _ := ctx.Value(trafficAuthorizationKey{}).(*TrafficAuthorization)
	return state
}
func TrafficAccessSessionFromContext(ctx context.Context) TrafficAccessSession {
	if state := TrafficAuthorizationFromContext(ctx); state != nil {
		return state.Session
	}
	return nil
}
func TrafficAccessDecision(ctx context.Context) *contract.Decision {
	if state := TrafficAuthorizationFromContext(ctx); state != nil {
		return state.Decision
	}
	return nil
}
func TrafficAuthorizationContext(ctx context.Context) context.Context {
	if state := TrafficAuthorizationFromContext(ctx); state != nil {
		return state.Context
	}
	return nil
}
func setTrafficAuthorization(ctx context.Context, session TrafficAccessSession, lifetime context.Context) {
	if owner := GetContextOrNil(ctx); owner != nil {
		state := &TrafficAuthorization{Session: session, Context: lifetime}
		if old := TrafficAuthorizationFromContext(ctx); old != nil {
			state.Decision = old.Decision
		}
		owner.authorization = state
	}
}
func recordTrafficAccessDecision(ctx context.Context, d contract.Decision) {
	if !d.Managed {
		return
	}
	if owner := GetContextOrNil(ctx); owner != nil {
		state := new(TrafficAuthorization)
		if old := TrafficAuthorizationFromContext(ctx); old != nil {
			*state = *old
		}
		state.Decision = new(d)
		owner.authorization = state
	}
}

// PinTrafficDestination resolves protected names locally, authorizes each actual
// address, and returns only the chosen permitted address. A proxy cannot resolve
// that name again to a different endpoint after the authorization check.
func PinTrafficDestination(ctx context.Context, access TrafficAccess, original Address) (Address, error) {
	return PinTrafficTarget(ctx, access, original, original)
}

func PinTrafficTarget(ctx context.Context, access TrafficAccess, original, target Address) (Address, error) {
	if access == nil {
		return target, nil
	}
	subject := TrafficSubjectFromContext(ctx)
	if err := access.Preflight(subject); err != nil {
		return nil, err
	}
	if !access.Managed(subject) {
		return target, nil
	}
	authorize := func(actual Address) bool {
		d := access.Decide(subject, original, actual)
		recordTrafficAccessDecision(ctx, d)
		return d.Allowed
	}
	if !target.IsFqdn() {
		if !authorize(target) {
			return nil, ErrTrafficAccessDenied
		}
		return target, nil
	}
	ips, err := ResolverIP(ctx, target.Hostname())
	if err != nil || ips == nil {
		return nil, ErrTrafficAccessDenied
	}
	families := [2][]net.IP{ips.A, ips.AAAA}
	if GetContext(ctx).ConnOptions().Resolver().Mode() == ResolverModePreferIPv6 {
		families = [2][]net.IP{ips.AAAA, ips.A}
	}
	for _, family := range families {
		for _, ip := range family {
			actual := ParseIPAddr(target.Network(), ip, target.Port())
			if authorize(actual) {
				return actual, nil
			}
		}
	}
	return nil, ErrTrafficAccessDenied
}

// connectionSlot also covers policy revocation while a dial is still pending.
// Publishing a later dial result into a closed slot closes it immediately.
type connectionSlot struct {
	mu      sync.Mutex
	conn    net.Conn
	closed  bool
	revoked bool
	err     error
}

func (s *connectionSlot) assign(conn net.Conn) bool {
	s.mu.Lock()
	if s.closed || s.revoked {
		s.mu.Unlock()
		_ = conn.Close()
		return false
	}
	s.conn = conn
	s.mu.Unlock()
	return true
}

func (s *connectionSlot) Interrupt() {
	s.mu.Lock()
	s.revoked = true
	conn := s.conn
	s.mu.Unlock()
	if conn != nil {
		_ = conn.SetDeadline(time.Now())
	}
}
func (s *connectionSlot) Close() error {
	s.mu.Lock()
	if s.closed {
		err := s.err
		s.mu.Unlock()
		return err
	}
	s.closed = true
	conn := s.conn
	s.mu.Unlock()
	var err error
	if conn != nil {
		err = conn.Close()
	}
	s.mu.Lock()
	s.err = err
	s.mu.Unlock()
	return err
}

// DialTraffic opens a revocable authorization before the transport handshake.
// The connection retains the authorization lifetime rather than the dial timeout.
func DialTraffic(ctx context.Context, access TrafficAccess, original, actual Address, dial func(context.Context, Address) (net.Conn, error)) (net.Conn, error) {
	subject := TrafficSubjectFromContext(ctx)
	if access == nil || !subject.External {
		return dial(ctx, actual)
	}
	parent := context.Background()
	if subject.Identity != nil && subject.Identity.Context != nil {
		parent = subject.Identity.Context
	}
	lifetime, revoke := context.WithCancelCause(parent)
	dialCtx, cancelDial := context.WithCancel(ctx)
	defer cancelDial()
	slot := new(connectionSlot)
	session, err := access.NewSession(subject, func(cause error) { revoke(cause); cancelDial(); slot.Interrupt() }, func() { _ = slot.Close() })
	if err != nil {
		revoke(err)
		return nil, err
	}
	if session == nil {
		revoke(ErrTrafficAccessDenied)
		return nil, ErrTrafficAccessDenied
	}
	if err := session.Authorize(original, actual); err != nil {
		session.Close()
		revoke(err)
		return nil, err
	}
	setTrafficAuthorization(ctx, session, lifetime)
	conn, err := dial(dialCtx, actual)
	if err != nil {
		session.Close()
		revoke(err)
		return nil, err
	}
	if IsNilConn(conn) {
		session.Close()
		revoke(ErrTrafficAccessDenied)
		return nil, fmt.Errorf("traffic dial returned an empty connection")
	}
	if !slot.assign(conn) {
		session.Close()
		revoke(ErrTrafficAccessDenied)
		return nil, ErrTrafficAccessDenied
	}
	return &trafficConn{Conn: conn, slot: slot, session: session, revoke: revoke}, nil
}

// BindTrafficConn covers local DNS and intercepted HTTP streams that never dial
// through Route.Conn. The adapter owns the returned connection and closes it.
func BindTrafficConn(ctx context.Context, access TrafficAccess, original, actual Address, conn net.Conn) (net.Conn, error) {
	return DialTraffic(ctx, access, original, actual, func(context.Context, Address) (net.Conn, error) { return conn, nil })
}

// AuthorizeTrafficRequest tracks a local operation without opening an outbound
// socket. The owner must release it when the asynchronous response completes.
func AuthorizeTrafficRequest(ctx context.Context, access TrafficAccess, original, actual Address) (context.Context, func(), error) {
	subject := TrafficSubjectFromContext(ctx)
	if access == nil || !subject.External {
		return ctx, func() {}, nil
	}
	lifetime, cancel := context.WithCancelCause(ctx)
	session, err := access.NewSession(subject, cancel)
	if err != nil || session == nil {
		cancel(ErrTrafficAccessDenied)
		if err == nil {
			err = ErrTrafficAccessDenied
		}
		return nil, nil, err
	}
	if err := session.Authorize(original, actual); err != nil {
		session.Close()
		cancel(err)
		return nil, nil, err
	}
	setTrafficAuthorization(ctx, session, lifetime)
	return WithTrafficAuthorization(lifetime, session, lifetime), func() { session.Close(); cancel(ErrTrafficSessionClosed) }, nil
}

type trafficConn struct {
	net.Conn
	slot    *connectionSlot
	session TrafficAccessSession
	revoke  context.CancelCauseFunc
}

func (c *trafficConn) Close() error {
	c.session.Close()
	err := c.slot.Close()
	c.revoke(ErrTrafficSessionClosed)
	return err
}
func (c *trafficConn) CloseWrite() error {
	if conn, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return conn.CloseWrite()
	}
	return errors.ErrUnsupported
}
func (c *trafficConn) CloseRead() error {
	if conn, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return conn.CloseRead()
	}
	return errors.ErrUnsupported
}
func (c *trafficConn) ReadFrom(r io.Reader) (int64, error) {
	if conn, ok := c.Conn.(io.ReaderFrom); ok {
		return conn.ReadFrom(r)
	}
	return io.Copy(c.Conn, r)
}
func (c *trafficConn) WriteTo(w io.Writer) (int64, error) {
	if conn, ok := c.Conn.(io.WriterTo); ok {
		return conn.WriteTo(w)
	}
	return io.Copy(w, c.Conn)
}

// ProxyIdentity remains stable across per-request authorization wrappers so
// Gateway pooling retains its existing identity and source isolation.
func ProxyIdentity(proxy Proxy) string {
	if identified, ok := proxy.(interface{ ConnectionPoolIdentity() string }); ok {
		return identified.ConnectionPoolIdentity()
	}
	return fmt.Sprintf("%T:%p", proxy, proxy)
}
