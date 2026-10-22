package netapi

import (
	"context"
	"errors"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxyauth"
)

type identityKey struct{}

func WithTrafficIdentity(ctx context.Context, identity *proxyauth.Identity) context.Context {
	if identity == nil {
		return ctx
	}
	return context.WithValue(ctx, identityKey{}, identity)
}
func TrafficIdentity(ctx context.Context) *proxyauth.Identity {
	identity, _ := ctx.Value(identityKey{}).(*proxyauth.Identity)
	return identity
}

// WithIdentityHandler propagates an authenticated identity on every traffic
// path and terminates active streams when its credential is invalidated.
func WithIdentityHandler(handler Handler, identity *proxyauth.Identity) Handler {
	if identity == nil {
		return handler
	}
	return &identityHandler{Handler: handler, identity: identity}
}

type identityHandler struct {
	Handler
	identity *proxyauth.Identity
}

func (h *identityHandler) HandleStream(meta *StreamMeta) {
	if !h.identity.Valid() {
		_ = meta.Src.Close()
		return
	}
	meta.Identity = h.identity
	conn := meta.Src
	wrapped := &identityConn{Conn: conn}
	wrapped.stop = context.AfterFunc(h.identity.Context, func() { _ = conn.Close() })
	meta.Src = wrapped
	h.Handler.HandleStream(meta)
}
func (h *identityHandler) HandlePacket(packet *Packet) {
	if !h.identity.Valid() {
		packet.DecRef()
		return
	}
	packet.Identity = h.identity
	h.Handler.HandlePacket(packet)
}
func (h *identityHandler) HandlePing(meta *PingMeta) {
	if !h.identity.Valid() {
		return
	}
	meta.Identity = h.identity
	write := meta.WriteBack
	meta.WriteBack = func(id uint64, err error) error {
		if !h.identity.Valid() {
			return proxyauth.ErrUnauthorized
		}
		return write(id, err)
	}
	h.Handler.HandlePing(meta)
}

type identityConn struct {
	net.Conn
	stop func() bool
}

func (c *identityConn) Close() error { c.stop(); return c.Conn.Close() }

func (c *identityConn) CloseWrite() error {
	if conn, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return conn.CloseWrite()
	}
	return errors.ErrUnsupported
}
func (c *identityConn) CloseRead() error {
	if conn, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return conn.CloseRead()
	}
	return errors.ErrUnsupported
}
