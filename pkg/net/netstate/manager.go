package netstate

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
)

var ErrInvalidated = errors.New("underlying network path is no longer valid")

// Default is fed by the existing platform monitor. Run owns its one cleanup
// worker; resource registration adds no watcher goroutines or packet-path work.
var Default = NewManager()

type Manager struct {
	mu       sync.Mutex
	current  atomic.Pointer[view]
	sequence uint64
	entries  map[*Registration]struct{}
	wake     chan struct{}
	running  atomic.Bool
}

func NewManager() *Manager {
	m := &Manager{entries: make(map[*Registration]struct{}), wake: make(chan struct{}, 1)}
	m.current.Store(&view{networks: make(map[string]networkView)})
	return m
}

// Apply publishes a successful snapshot before queuing cleanup. It performs
// no network I/O or resource callbacks. Repeated identical observations are
// idempotent, and registrations detached by an event retain their original
// resource closure, so delayed cleanup cannot affect a replacement socket.
func (m *Manager) Apply(s Snapshot, routeChanged bool) Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.applyLocked(s, routeChanged)
}

func (m *Manager) applyLocked(s Snapshot, routeChanged bool) Event {
	old := m.current.Load()
	e := Event{Generation: old.generation, Source: s.Source}
	if routeChanged {
		e.Changes |= RouteChanged
	}
	if old.matches(s) {
		if routeChanged {
			RouteEvents.Inc()
		} else {
			DuplicateEvents.Inc()
		}
		return e
	}
	next := &view{networks: make(map[string]networkView, len(s.Networks)), selected: s.Selected, lastSelected: old.lastSelected, generation: old.generation}
	if s.Selected != "" {
		next.lastSelected = s.Selected
	}
	for _, raw := range s.Networks {
		if raw.ID == "" {
			continue // unsupported/unknown identity cannot justify invalidation
		}
		n := networkView{Network: cloneNetwork(raw), addresses: make(map[netip.Addr]uint64, len(raw.Addresses))}
		prev, exists := old.networks[n.ID]
		n.epoch, n.v4, n.v6, n.anyFamily = prev.epoch, prev.v4, prev.v6, prev.anyFamily
		if !exists || prev.Available != n.Available {
			m.sequence++
			n.epoch = m.sequence
			if exists {
				e.Changes |= ConnectivityChanged
			} else {
				e.Changes |= NetworkChanged
			}
		}
		for _, ip := range raw.Addresses {
			ip = ip.Unmap()
			if !ip.IsValid() || ip.IsUnspecified() {
				continue
			}
			token := prev.addresses[ip]
			if token == 0 || n.epoch != prev.epoch {
				m.sequence++
				token = m.sequence
			}
			n.addresses[ip] = token
		}
		if exists && !sameAddresses(prev.addresses, n.addresses) {
			e.Changes |= NetworkChanged
		}
		for _, family := range []struct {
			bits  uint8
			token *uint64
		}{{4, &n.v4}, {6, &n.v6}, {0, &n.anyFamily}} {
			if *family.token == 0 || !commonAddress(prev.addresses, n.addresses, family.bits) {
				// Empty -> empty is unchanged; keep its token as well.
				if !sameAddresses(prev.addresses, n.addresses) || *family.token == 0 {
					m.sequence++
					*family.token = m.sequence
				}
			}
		}
		next.networks[n.ID] = n
	}
	for id, previous := range old.networks {
		if _, ok := next.networks[id]; !ok && previous.Available {
			e.Changes |= NetworkChanged
		}
	}
	if old.lastSelected != "" && old.lastSelected != next.lastSelected {
		e.Changes |= NetworkChanged
	}
	if e.Changes&(NetworkChanged|ConnectivityChanged) != 0 {
		next.generation++
		e.Generation = next.generation
		TransitionEvents.Inc()
	} else if routeChanged {
		RouteEvents.Inc()
	}
	m.current.Store(next)
	if e.Changes&(NetworkChanged|ConnectivityChanged) != 0 {
		for r := range m.entries {
			if !r.invalid && !next.valid(r.path) {
				r.invalid = true
				r.event = e
				m.signal()
			}
		}
	}
	return e
}

// InterfaceUnavailable records authoritative deletion/down notifications
// before debouncing. A delete/recreate burst must not hide an interface
// lifetime, even when the OS reuses both its name and index.
func (m *Manager) InterfaceUnavailable(index int) Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	old := m.current.Load()
	s := Snapshot{Selected: old.selected, Source: PlatformCallback}
	changed := false
	for _, n := range old.networks {
		raw := n.Network
		if raw.Index == index && raw.Available {
			raw.Available = false
			changed = true
		}
		s.Networks = append(s.Networks, raw)
	}
	if changed {
		e := m.applyLocked(s, false)
		e.InterfaceIndex = index
		return e
	}
	return Event{}
}

// AddressUnavailable handles authoritative DELADDR before event coalescing can
// hide a remove/re-add cycle. Other sources/families keep their path tokens.
func (m *Manager) AddressUnavailable(index int, address netip.Addr) Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	old := m.current.Load()
	s := Snapshot{Selected: old.selected, Source: PlatformCallback}
	changed := false
	for _, n := range old.networks {
		raw := cloneNetwork(n.Network)
		if n.Index == index {
			raw.Addresses = raw.Addresses[:0]
			for ip := range n.addresses {
				if ip == address.Unmap() {
					changed = true
				} else {
					raw.Addresses = append(raw.Addresses, ip)
				}
			}
		}
		s.Networks = append(s.Networks, raw)
	}
	if changed {
		e := m.applyLocked(s, false)
		e.InterfaceIndex = index
		return e
	}
	return Event{}
}

// Capture is a connection-creation operation, never a read/write operation.
// An actual local source address takes precedence over a route-derived hint.
// Ambiguous source addresses (e.g. overlapping namespaces) remain unknown.
func (m *Manager) Capture(iface string, local netip.Addr, family uint8) Path {
	v := m.current.Load()
	local = local.Unmap()
	if local.IsUnspecified() {
		local = netip.Addr{}
	}
	var found networkView
	count := 0
	for _, n := range v.networks {
		if !n.Available {
			continue
		}
		if !local.IsValid() {
			usable := false
			for ip := range n.addresses {
				if family == 0 || family == 4 && ip.Is4() || family == 6 && ip.Is6() {
					usable = true
					break
				}
			}
			if !usable {
				continue
			}
		}
		if local.IsValid() {
			if _, ok := n.addresses[local]; !ok {
				continue
			}
			if iface != "" && n.Name != iface {
				continue
			}
		} else if iface != "" {
			if n.Name != iface {
				continue
			}
		} else if v.selected == "" || n.ID != v.selected {
			continue
		}
		found = n
		count++
	}
	if count != 1 {
		return Path{}
	}
	p := Path{network: found.ID, epoch: found.epoch, local: local, address: found.addresses[local], family: family, token: found.anyFamily}
	switch family {
	case 4:
		p.token = found.v4
	case 6:
		p.token = found.v6
	}
	return p
}

func (m *Manager) Valid(p Path) bool { return m.current.Load().valid(p) }

// CaptureNetwork records an OS-confirmed socket binding, never a default-route
// guess. An unobserved Network remains unknown even if another has the same IP.
func (m *Manager) CaptureNetwork(id string, local netip.Addr, family uint8) Path {
	n, ok := m.current.Load().networks[id]
	if !ok || !n.Available {
		return Path{}
	}
	local = local.WithZone("").Unmap()
	if local.IsUnspecified() {
		local = netip.Addr{}
	}
	if local.IsValid() && n.addresses[local] == 0 {
		return Path{}
	}
	if !local.IsValid() {
		usable := false
		for ip := range n.addresses {
			if family == 0 || family == 4 && ip.Is4() || family == 6 && ip.Is6() {
				usable = true
				break
			}
		}
		if !usable {
			return Path{}
		}
	}
	p := Path{network: id, epoch: n.epoch, local: local, address: n.addresses[local], family: family, token: n.anyFamily}
	switch family {
	case 4:
		p.token = n.v4
	case 6:
		p.token = n.v6
	}
	return p
}

// Registration owns exactly one resource. Close unregisters it; it does not
// close the resource. A callback already running may finish after Close, so
// callbacks must target the captured resource, never a mutable owner slot.
type Registration struct {
	manager  *Manager
	path     Path
	callback func(Event)
	invalid  bool // guarded by manager.mu
	event    Event
}

func (m *Manager) Register(p Path, callback func(Event)) *Registration {
	if !p.Known() || callback == nil {
		return nil
	}
	r := &Registration{manager: m, path: p, callback: callback}
	m.mu.Lock()
	m.entries[r] = struct{}{}
	if !m.current.Load().valid(p) {
		r.invalid = true
		r.event = Event{Changes: NetworkChanged, Generation: m.current.Load().generation}
		m.signal()
	}
	m.mu.Unlock()
	return r
}

func (r *Registration) Close() error {
	if r != nil {
		r.manager.mu.Lock()
		delete(r.manager.entries, r)
		r.manager.mu.Unlock()
	}
	return nil
}

func (m *Manager) signal() {
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

// Run processes invalidations serially outside all monitor/route/resource
// locks. Multiple monitor owners may call Run; only one worker is active.
// Cancellation stops dispatch without destroying sockets or valid affinity.
func (m *Manager) Run(ctx context.Context) {
	if !m.running.CompareAndSwap(false, true) {
		return
	}
	defer m.running.Store(false)
	for {
		select {
		case <-ctx.Done():
			return
		case <-m.wake:
			for ctx.Err() == nil {
				batch := m.takeInvalid()
				if len(batch) == 0 {
					break
				}
				for _, r := range batch {
					Invalidations.Inc()
					r.callback(r.event)
				}
			}
		}
	}
}

func (m *Manager) takeInvalid() []*Registration {
	m.mu.Lock()
	defer m.mu.Unlock()
	var batch []*Registration
	for r := range m.entries {
		if r.invalid {
			delete(m.entries, r)
			batch = append(batch, r)
			if len(batch) == 64 {
				break
			}
		}
	}
	return batch
}

// Refresh never interprets a provider error as an empty/offline network.
func (m *Manager) Refresh(provider func() (Snapshot, error), routeChanged bool) (Event, error) {
	s, err := provider()
	if err != nil {
		return Event{}, err
	}
	return m.Apply(s, routeChanged), nil
}
