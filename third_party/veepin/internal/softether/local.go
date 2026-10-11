package softether

// The server's own attachment to the switch.
//
// Until this existed, `softether serve` opened a TAP, reported its name, closed
// it on shutdown, and never read or wrote a single frame through it. The switch
// forwarded between *sessions* only — forwardTo walked destination ports and
// looked each one up in the session table, so a port that was not a client had
// nowhere to be delivered to and the host's own interface was not on the switch
// at all.
//
// That is why every SoftEther cell in the interop matrix was a dash. It was
// read as "the cells have not been built yet"; building one showed it was "the
// data path does not exist". See doc/operability-plan.md item 13.
//
// A local port is an ordinary bridge port whose delivery is a function call
// rather than a TLS write. Making it ordinary is the point: the bridge already
// learns MACs per port, floods to unlearned destinations and excludes the
// source, and none of that needs to know which ports are sessions.

// localPort is the server's TAP as a switch port: a port id and the function
// that hands a frame to it.
type localPort struct {
	id    PortID
	write func(frame []byte) error
}

// AttachLocal puts the server's own interface on the switch and returns its
// port. write is called with each frame the switch decides belongs there; it
// must be safe to call from the goroutine of whichever session forwarded.
//
// Calling it twice replaces the first attachment, which is what a caller that
// rebuilds its TAP wants and is cheaper to reason about than an error nobody
// would handle.
func (s *Server) AttachLocal(write func(frame []byte) error) PortID {
	p := s.bridge.NewPort()
	s.localMu.Lock()
	s.local = &localPort{id: p, write: write}
	s.localMu.Unlock()
	return p
}

// DetachLocal removes the server's interface from the switch, so frames stop
// being handed to a writer whose device is closing.
func (s *Server) DetachLocal() {
	s.localMu.Lock()
	l := s.local
	s.local = nil
	s.localMu.Unlock()
	if l != nil {
		s.bridge.RemovePort(l.id)
	}
}

// InjectLocal switches one frame that arrived on the server's own interface,
// exactly as frameLoop does for one that arrived on a session.
//
// It is the mirror of frameLoop's body and deliberately shares deliver with it:
// the learning, the flood-on-unknown-destination and the source exclusion are
// the switch's behaviour, and a second copy of them here is how the two paths
// would drift.
func (s *Server) InjectLocal(frame []byte) {
	s.localMu.RLock()
	l := s.local
	s.localMu.RUnlock()
	if l == nil {
		return
	}
	parsed, ok := ParseFrame(frame)
	if !ok {
		return
	}
	result := s.bridge.Forward(parsed, l.id)
	dests := result.Destinations
	if dests == nil {
		dests = s.bridge.FloodPorts(l.id)
	}
	s.deliver(dests, frame, l.id)
}

// deliver writes one frame to every destination port that can take it: a
// session's TLS connection, or the local interface. from is excluded, because a
// switch never sends a frame back out the port it arrived on.
//
// A write failure is the destination's problem, not the sender's: a client must
// not be torn down because a different one went away, or because the host's TAP
// is momentarily full.
func (s *Server) deliver(dests []PortID, frame []byte, from PortID) {
	s.localMu.RLock()
	local := s.local
	s.localMu.RUnlock()

	for _, p := range dests {
		if p == from {
			continue
		}
		if local != nil && p == local.id {
			if err := local.write(frame); err != nil {
				s.logf("softether: forward to the local interface: %v", err)
			}
			continue
		}
		peer := s.sessionFor(p)
		if peer == nil || !peer.authenticated.Load() {
			continue
		}
		if err := peer.writeFrame(frame); err != nil {
			s.logf("softether: forward to port %d: %v", p, err)
		}
	}
}
