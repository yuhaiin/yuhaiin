//go:build linux && !android

package sshserver

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/processnet"
	"github.com/yuhaiin/sessionnet"
)

// connectionNetwork holds one session (namespaces, PID 1 supervisor, TUN)
// and lightweight stack per authenticated SSH transport. Each shell, exec or
// SFTP channel holds exactly one lease. SSH connections never share their
// localhost, resolver or packet-processing state.
type connectionNetwork struct {
	server *Server
	ctx    context.Context
	mu     sync.Mutex
	owner  *sessionnet.Session
	flows  io.Closer
	refs   int
	closed bool
}

// acquire serializes first-use initialization. A command cannot start until
// the shared IP stack is ready. Failed initialization never falls back to the
// host network. A zero refcount tears down all three shared resources.
func (g *connectionNetwork) acquire() (*sessionnet.Session, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return nil, os.ErrClosed
	}
	if err := g.ctx.Err(); err != nil {
		return nil, err
	}
	if g.owner == nil {
		if err := g.openLocked(); err != nil {
			return nil, err
		}
	}
	select {
	case <-g.owner.Done():
		// The supervisor died (for example it was killed from outside).
		// Never reuse the dead session; replace it with a fresh one.
		resources := g.detachLocked()
		resources.close()
		if err := g.openLocked(); err != nil {
			return nil, err
		}
	default:
	}
	g.refs++
	return g.owner, nil
}

func (g *connectionNetwork) openLocked() (err error) {
	// The session supervisor keeps the namespaces alive without any SSH
	// channel. Its processes have no network access except through the TUN
	// connected to the Yuhaiin lightweight stack.
	s := g.server
	owner, err := sessionnet.Open(g.ctx, sessionConfig(s.config, s.addresses, s.cgroups))
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = owner.Close()
		}
	}()
	link, err := processnet.Attach(owner, s.handler, s.addresses, s.config.MTU, s.config.IPv6, "ssh")
	if err != nil {
		return err
	}
	var flows io.Closer = link
	if len(s.config.HostLoopback) != 0 {
		// Serve the forwarded loopback endpoints before any command runs,
		// so a session never sees them refuse connections.
		forward, err := processnet.StartHostLoopback(owner, s.config.HostLoopback, s.config.HostLoopbackDialer, link.ProcessScope(), s.config.InboundID)
		if err != nil {
			_ = link.Close()
			slog.Error("ssh inbound: host loopback forwarding failed", "inbound", s.config.InboundID, "reason", err.Error())
			return err
		}
		flows = closers{forward, link}
	}
	if err = owner.Release(); err != nil {
		_ = flows.Close()
		return err
	}
	g.owner, g.flows = owner, flows
	return nil
}

func (g *connectionNetwork) release() {
	g.mu.Lock()
	if g.refs == 0 {
		g.mu.Unlock()
		return
	}
	g.refs--
	if g.refs != 0 {
		g.mu.Unlock()
		return
	}
	resources := g.detachLocked()
	g.mu.Unlock()
	resources.close()
}

// detachLocked moves all owned resources out while g.mu is held.
func (g *connectionNetwork) detachLocked() networkResources {
	r := networkResources{g.owner, g.flows}
	g.owner, g.flows = nil, nil
	return r
}

// closers closes in order and reports every error.
type closers []io.Closer

func (c closers) Close() error {
	var err error
	for _, closer := range c {
		err = errors.Join(err, closer.Close())
	}
	return err
}

type networkResources struct {
	owner *sessionnet.Session
	flows io.Closer
}

// close kills every session process (PID namespace and cgroup), then stops
// the packet stack. Cleanup errors may contain credentials from the
// underlying transport or routing stack, so only a fixed component label is
// logged, never the raw error.
func (r networkResources) close() {
	owner, flows := r.owner, r.flows
	if owner != nil {
		if err := owner.Close(); err != nil {
			slog.Error("ssh inbound: isolated session cleanup failed", "component", "namespace")
		}
	}
	if flows != nil {
		if err := flows.Close(); err != nil {
			slog.Error("ssh inbound: isolated session cleanup failed", "component", "packet stack")
		}
	}
}

// Close cancels network access when the SSH transport closes. Any active
// command is separately canceled by its session context.
func (g *connectionNetwork) Close() {
	g.mu.Lock()
	g.closed = true
	resources := g.detachLocked()
	g.mu.Unlock()
	resources.close()
}
