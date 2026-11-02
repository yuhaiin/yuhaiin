//go:build linux && !android

package sshserver

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/lightweight"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/lightweighttun"
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
	fd, err := owner.DupTun()
	if err != nil {
		return err
	}
	addresses := []netip.Prefix{netip.PrefixFrom(s.addresses.GatewayIPv4, 32)}
	ips := []netip.Addr{s.addresses.GatewayIPv4}
	if s.config.IPv6 {
		addresses = append(addresses, netip.PrefixFrom(s.addresses.GatewayIPv6, 128))
		ips = append(ips, s.addresses.GatewayIPv6)
	}
	stack, err := lightweight.New(lightweight.Config{
		Addresses: ips, MTU: s.config.MTU,
		Promiscuous: true, ForwardUDP: true, Profile: lightweight.LocalTun,
	}, &tunPackets{File: fd})
	if err != nil {
		_ = fd.Close()
		return err
	}
	flows, err := lightweighttun.NewFromStack(stack, s.handler, addresses, "ssh")
	if err != nil {
		_ = stack.Close()
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
	owner, flows, keepalive := g.detachLocked()
	g.mu.Unlock()
	closeConnectionNetwork(owner, flows, keepalive)
}

// detachLocked moves all owned resources out while g.mu is held.
func (g *connectionNetwork) detachLocked() (*sessionnet.Session, io.Closer, *os.File) {
	owner, flows, keepalive := g.owner, g.flows, g.keepalive
	g.owner, g.flows, g.keepalive = nil, nil, nil
	return owner, flows, keepalive
}

func closeConnectionNetwork(owner *sessionnet.Session, flows io.Closer, keepalive *os.File) {
	var err error
	if keepalive != nil {
		err = errors.Join(err, keepalive.Close())
	}
	if owner != nil {
		err = errors.Join(err, owner.Close())
	}
	if flows != nil {
		err = errors.Join(err, flows.Close())
	}
	if err != nil {
		slog.Error("ssh inbound: failed to clean up isolated session networking", "error", err)
	}
}

// Close cancels network access when the SSH transport closes. Any active
// command is separately canceled by its session context.
func (g *connectionNetwork) Close() {
	g.mu.Lock()
	g.closed = true
	owner, flows, keepalive := g.detachLocked()
	g.mu.Unlock()
	closeConnectionNetwork(owner, flows, keepalive)
}
