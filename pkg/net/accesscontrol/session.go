package accesscontrol

import (
	"context"
	"net"
	"net/netip"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

type targetKey struct {
	originalIP     netip.AddrPort
	originalDomain string
	originalPort   uint16
	resolvedIP     netip.AddrPort
	resolvedDomain string
	network        string
}
type target struct {
	original, resolved netapi.Address
	epoch              *Prepared
}

type firstTarget struct {
	key   targetKey
	value target
}

// Session owns only a subject and bounded target authorizations, not policy
// trees or user/group objects. One UDP source keeps its shared full-cone socket.
type Session struct {
	owner             *Controller
	subject           netapi.TrafficSubject
	mu                sync.Mutex
	revoked, released bool
	stop              func() bool
	cancelTraffic     func(error)
	terminateTraffic  func()
	targets           map[targetKey]target
	first             *firstTarget
	candidate         netapi.IPAddr
}

func authorizationKey(original netapi.Address, network string) targetKey {
	key := targetKey{network: network}
	if original != nil {
		key.originalPort = original.Port()
		if original.IsFqdn() {
			key.originalDomain = original.Hostname()
		} else {
			key.originalIP = original.(netapi.IPAddress).AddrPort()
		}
	}
	return key
}

func resolvedKey(original netapi.Address, real net.Addr) (targetKey, netapi.IPAddr, netapi.Address, error) {
	var address netip.AddrPort
	switch a := real.(type) {
	case netapi.IPAddress:
		address = a.AddrPort()
	case *net.UDPAddr:
		address = a.AddrPort()
	case *net.TCPAddr:
		address = a.AddrPort()
	case netapi.DomainAddress:
		if !a.IsFqdn() {
			return targetKey{}, netapi.IPAddr{}, nil, netapi.ErrTrafficAccessDenied
		}
		key := authorizationKey(original, a.Network())
		key.resolvedDomain = a.Hostname()
		return key, netapi.IPAddr{}, a, nil
	default:
		return targetKey{}, netapi.IPAddr{}, nil, netapi.ErrTrafficAccessDenied
	}
	if !address.IsValid() || address.Addr().Zone() != "" {
		return targetKey{}, netapi.IPAddr{}, nil, netapi.ErrTrafficAccessDenied
	}
	network := real.Network()
	if original != nil && netapi.ParseAddressNetwork(original.Network()) != netapi.ParseAddressNetwork(network) {
		return targetKey{}, netapi.IPAddr{}, nil, netapi.ErrTrafficAccessDenied
	}
	resolved := netapi.IPAddr{AddressNetwork: netapi.ParseAddressNetwork(network), AddrPortX: netip.AddrPortFrom(address.Addr().Unmap(), address.Port())}
	key := authorizationKey(original, network)
	key.resolvedIP = resolved.AddrPort()
	return key, resolved, nil, nil
}

func (s *Session) Authorize(original netapi.Address, real net.Addr) error {
	key, ip, domain, err := resolvedKey(original, real)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.revoked || s.released || s.owner.closed.Load() || s.subject.Identity != nil && !validIdentity(s.subject) {
		return netapi.ErrTrafficAccessDenied
	}
	epoch := s.owner.active.Load()
	if s.first != nil && s.first.key == key && s.first.value.epoch == epoch {
		return nil
	}
	if old, ok := s.targets[key]; ok && old.epoch == epoch {
		return nil
	}
	s.candidate = ip
	var resolved netapi.Address = &s.candidate
	if domain != nil {
		resolved = domain
	}
	decision := s.owner.decision(epoch, s.subject, original, resolved)
	if !decision.Allowed {
		s.owner.denied.Add(1)
		return netapi.ErrTrafficAccessDenied
	}
	if s.first != nil && s.first.key == key {
		s.first.value.epoch = epoch
		return nil
	}
	if old, ok := s.targets[key]; ok {
		old.epoch = epoch
		s.targets[key] = old
		return nil
	}
	if len(s.targets) >= maxSessionTargets-1 {
		s.owner.capacityRejected.Add(1)
		return netapi.ErrTrafficAccessDenied
	}
	for {
		count := s.owner.targets.Load()
		if count >= maxTargets {
			s.owner.capacityRejected.Add(1)
			return netapi.ErrTrafficAccessDenied
		}
		if s.owner.targets.CompareAndSwap(count, count+1) {
			break
		}
	}
	// Retain the address only on a new authorization. Cached packet checks do not
	// allocate a target object, copy a tree, or reevaluate group membership.
	if domain == nil {
		resolved = new(ip)
	}
	value := target{original: original, resolved: resolved, epoch: epoch}
	if s.first == nil {
		// Most TCP streams and UDP sources have one target. Keep it outside a
		// map to avoid a large initial bucket and hashing on cached datagrams.
		s.first = &firstTarget{key: key, value: value}
	} else {
		if s.targets == nil {
			s.targets = make(map[targetKey]target)
		}
		s.targets[key] = value
	}
	return nil
}

func (s *Session) revalidate(epoch *Prepared) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.revoked || s.released {
		return false
	}
	if s.owner.closed.Load() || s.subject.Identity != nil && !validIdentity(s.subject) || epoch.managed(s.subject) && (!validIdentity(s.subject) || s.subject.InboundID == "") {
		s.revoked = true
		return true
	}
	if s.first != nil {
		t := &s.first.value
		if !s.owner.decision(epoch, s.subject, t.original, t.resolved).Allowed {
			s.revoked = true
			return true
		}
		t.epoch = epoch
	}
	for key, t := range s.targets {
		if !s.owner.decision(epoch, s.subject, t.original, t.resolved).Allowed {
			s.revoked = true
			return true
		}
		t.epoch = epoch
		s.targets[key] = t
	}
	return false
}

func (s *Session) invalidate() {
	s.mu.Lock()
	if s.revoked || s.released {
		s.mu.Unlock()
		return
	}
	s.revoked = true
	s.mu.Unlock()
	s.owner.revoked.Add(1)
	cause := error(context.Canceled)
	if s.subject.Identity != nil && !s.subject.Identity.Valid() {
		cause = context.Cause(s.subject.Identity.Context)
	}
	s.cancelTraffic(cause)
	s.Close()
	if s.terminateTraffic != nil {
		s.terminateTraffic()
	}
}

func (s *Session) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	if s.released {
		s.mu.Unlock()
		return
	}
	s.released = true
	count := len(s.targets)
	if s.first != nil {
		count++
		s.first = nil
	}
	clear(s.targets)
	stop := s.stop
	s.mu.Unlock()
	if stop != nil {
		stop()
	}
	s.owner.targets.Add(-int64(count))
	s.owner.mu.Lock()
	delete(s.owner.sessions, s)
	s.owner.mu.Unlock()
}
