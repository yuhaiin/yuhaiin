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

// connectionNetwork holds one namespace, TUN and lightweight stack per
// authenticated SSH transport. Each shell or exec holds exactly one lease.
// SSH connections never share their localhost or packet-processing state.
type connectionNetwork struct {
	server    *Server
	ctx       context.Context
	mu        sync.Mutex
	owner     *sessionnet.Session
	flows     io.Closer
	keepalive *os.File
	refs      int
	closed    bool
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
		return nil, errors.New("ssh inbound: shared namespace owner exited")
	default:
	}
	g.refs++
	return g.owner, nil
}

func (g *connectionNetwork) openLocked() (err error) {
	// A private pipe holds an unprivileged namespace owner alive without
	// keeping any SSH channel open. The owner has no network access except
	// through the TUN connected to the Yuhaiin lightweight stack.
	read, write, err := os.Pipe()
	if err != nil {
		return err
	}
	defer read.Close()
	defer func() {
		if err != nil {
			_ = write.Close()
		}
	}()

	s := g.server
	owner, err := sessionnet.Open(g.ctx, sessionnet.Config{
		Command:    []string{"/bin/sh", "-c", "read -r keepalive"},
		Credential: &sessionnet.Credential{UID: s.config.UID, GID: s.config.GID},
		Stdin:      read, MTU: s.config.MTU, IPv6: s.config.IPv6,
		Addresses: s.addresses,
		Cgroup:    s.cgroups,
	})
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = owner.Close()
		}
	}()
	flows, err := processnet.Attach(owner, s.handler, s.addresses, s.config.MTU, s.config.IPv6, "ssh")
	if err != nil {
		return err
	}
	if err = owner.Release(); err != nil {
		_ = flows.Close()
		return err
	}
	g.owner, g.flows, g.keepalive = owner, flows, write
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
	r := networkResources{g.owner, g.flows, g.keepalive}
	g.owner, g.flows, g.keepalive = nil, nil, nil
	return r
}

type networkResources struct {
	owner     *sessionnet.Session
	flows     io.Closer
	keepalive *os.File
}

func (r networkResources) close() {
	owner, flows, keepalive := r.owner, r.flows, r.keepalive
	// Cleanup errors may contain credentials from the underlying transport or
	// routing stack. Only log a fixed component label, never the raw error.
	if keepalive != nil {
		if err := keepalive.Close(); err != nil {
			slog.Error("ssh inbound: isolated session cleanup failed", "component", "keepalive")
		}
	}
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
