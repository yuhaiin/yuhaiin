//go:build linux && !android

package sshserver

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"strconv"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/netlink"
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
	processes *netlink.NetNSProcessDumper
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
	processes, err := openProcessDumper(owner)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = processes.Close()
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
	flows, err := lightweighttun.NewFromStack(stack, &scopedHandler{Handler: s.handler, scope: processes}, addresses, "ssh")
	if err != nil {
		_ = stack.Close()
		return err
	}
	if err = owner.Release(); err != nil {
		_ = flows.Close()
		return err
	}
	g.owner, g.flows, g.keepalive, g.processes = owner, flows, write, processes
	return nil
}

// openProcessDumper binds process lookups to the owner's network namespace.
// Spawned shells join that same namespace, so it covers every command of
// this SSH transport and nothing else.
func openProcessDumper(owner *sessionnet.Session) (*netlink.NetNSProcessDumper, error) {
	ns, err := os.Open("/proc/" + strconv.Itoa(owner.PID()) + "/ns/net")
	if err != nil {
		return nil, err
	}
	defer ns.Close()
	// The owner is reaped only after Done closes, so if it is still open the
	// PID could not have been recycled before the namespace file was opened.
	select {
	case <-owner.Done():
		return nil, errors.New("ssh inbound: shared namespace owner exited")
	default:
	}
	return netlink.NewNetNSProcessDumper(ns)
}

// scopedHandler tags every flow with the namespace that produced it, so
// process lookup and UDP NAT never confuse transports that share addresses.
type scopedHandler struct {
	netapi.Handler
	scope netapi.ProcessDumper
}

func (h *scopedHandler) HandleStream(meta *netapi.StreamMeta) {
	meta.ProcessScope = h.scope
	h.Handler.HandleStream(meta)
}

func (h *scopedHandler) HandlePacket(packet *netapi.Packet) {
	packet.ProcessScope = h.scope
	h.Handler.HandlePacket(packet)
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
	r := networkResources{g.owner, g.flows, g.keepalive, g.processes}
	g.owner, g.flows, g.keepalive, g.processes = nil, nil, nil, nil
	return r
}

type networkResources struct {
	owner     *sessionnet.Session
	flows     io.Closer
	keepalive *os.File
	processes *netlink.NetNSProcessDumper
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
	// Close after the stack so no new flow carries a closed scope; in-flight
	// lookups finish first and later ones fail without a host fallback.
	if r.processes != nil {
		_ = r.processes.Close()
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
