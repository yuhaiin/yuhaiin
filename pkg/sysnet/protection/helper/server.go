package helper

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/contract/sysnet"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/sysnet/iface"
	"github.com/Asutorufa/yuhaiin/pkg/sysnet/policy"
	"github.com/Asutorufa/yuhaiin/pkg/sysnet/protection"
	"github.com/Asutorufa/yuhaiin/pkg/sysnet/protection/pf"
)

// Config wires a Server to the system. Production values come from
// NewConfig; tests point the paths into a scratch directory.
type Config struct {
	StateFile string
	Socket    string
	Engine    *pf.Engine
	// BootID identifies the current boot session.
	BootID func() string
	// Group returns the gid of the socket group, creating the group if needed.
	Group func(ctx context.Context) (int, error)
	// Interfaces lists the system's interfaces.
	Interfaces func() ([]iface.Info, error)
	// PeerUID returns the user id of a connected client.
	PeerUID func(net.Conn) (int, error)
	// Verify is how often the OS state is checked and repaired.
	Verify time.Duration
	Now    func() time.Time
}

// runtimePolicy is the part of a policy bound to one client connection.
type runtimePolicy struct {
	conn    uint64
	tunnels []protection.Tunnel
	own     bool
}

// Server is the protection service.
type Server struct {
	cfg Config

	mu          sync.Mutex
	state       State
	stateExists bool
	stateErr    error
	runtime     *runtimePolicy
	conns       uint64
	// last apply results
	effective   bool
	waiting     bool
	applyErr    error
	updatedAt   int64
	loadedID    string
	preexisting bool
	// heals records when the main ruleset reference had to be restored,
	// so the service stops fighting a program that keeps replacing it.
	heals    []time.Time
	gid      int
	gidErr   error
	modified string
	open     map[net.Conn]bool
	// damaged is set after a damaged state file was replaced.
	damaged string
}

func NewServer(cfg Config) *Server {
	if cfg.Verify == 0 {
		cfg.Verify = 5 * time.Second
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Interfaces == nil {
		cfg.Interfaces = iface.List
	}
	return &Server{cfg: cfg}
}

// Run serves until ctx ends. Leaving never removes protection rules.
func (s *Server) Run(ctx context.Context) error {
	ln, err := s.listen()
	if err != nil {
		return err
	}
	defer ln.Close()
	s.mu.Lock()
	if s.cfg.Group != nil {
		s.gid, s.gidErr = s.cfg.Group(ctx)
		if s.gidErr != nil {
			log.Error("network protection: socket group unavailable; Yuhaiin's own connections will be blocked while protection is on", "err", s.gidErr)
		}
	}
	s.reconcileLocked(ctx, "service started")
	s.mu.Unlock()

	var wg sync.WaitGroup
	defer wg.Wait()
	wg.Go(func() {
		ticker := time.NewTicker(s.cfg.Verify)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.mu.Lock()
				s.reconcileLocked(ctx, "verify")
				s.mu.Unlock()
			}
		}
	})
	go func() {
		<-ctx.Done()
		_ = ln.Close()
		// Open client connections end with the service.
		s.mu.Lock()
		for c := range s.open {
			_ = c.Close()
		}
		s.mu.Unlock()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		wg.Go(func() { s.serve(ctx, conn) })
	}
}

func (s *Server) listen() (net.Listener, error) {
	if info, err := os.Lstat(s.cfg.Socket); err == nil {
		if info.Mode()&fs.ModeSocket == 0 {
			return nil, fmt.Errorf("%s exists and is not a socket", s.cfg.Socket)
		}
		_ = os.Remove(s.cfg.Socket)
	}
	ln, err := net.Listen("unix", s.cfg.Socket)
	if err != nil {
		return nil, err
	}
	// Anyone may ask for status; changes are checked per request against
	// the peer's user id.
	if err := os.Chmod(s.cfg.Socket, 0o666); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}

func (s *Server) serve(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	s.mu.Lock()
	s.conns++
	id := s.conns
	if s.open == nil {
		s.open = map[net.Conn]bool{}
	}
	s.open[conn] = true
	s.mu.Unlock()
	uid := -1
	if s.cfg.PeerUID != nil {
		if v, err := s.cfg.PeerUID(conn); err == nil {
			uid = v
		}
	}
	defer func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		delete(s.open, conn)
		if ctx.Err() != nil {
			// Shutting down: the rules stay as they are.
			return
		}
		if s.runtime != nil && s.runtime.conn == id {
			// The Yuhaiin process is gone: its TUNs and its sockets lose
			// their allowance at once.
			s.runtime = nil
			s.reconcileLocked(ctx, "Yuhaiin disconnected")
		}
	}()
	reader := bufio.NewReaderSize(conn, maxFrame)
	for {
		var req Request
		if err := readFrame(reader, &req); err != nil {
			return
		}
		resp := s.handle(ctx, id, uid, req)
		if err := writeFrame(conn, resp); err != nil {
			return
		}
	}
}

func problemResponse(id uint64, code, message, hint string) Response {
	return Response{ID: id, Error: &sysnet.ProtectionProblem{Code: code, Message: message, Hint: hint}}
}

func (s *Server) handle(ctx context.Context, conn uint64, uid int, req Request) Response {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch req.Op {
	case OpStatus:
	case OpEnable, OpUpdate, OpDisable:
		if uid != 0 {
			return problemResponse(req.ID, sysnet.ProblemPermission, "Changing Network Protection requires administrator rights", "Run Yuhaiin as the system service, or the command with sudo")
		}
	default:
		return problemResponse(req.ID, sysnet.ProblemPolicySync, fmt.Sprintf("unknown operation %q", req.Op), "")
	}
	by := req.By
	if by == "" {
		by = "api"
	}
	var err error
	switch req.Op {
	case OpEnable, OpUpdate:
		if req.Policy == nil {
			return problemResponse(req.ID, sysnet.ProblemPolicySync, "the request has no policy", "")
		}
		if err := s.check(*req.Policy); err != nil {
			status := s.statusLocked(ctx)
			return Response{ID: req.ID, Status: &status, Error: &sysnet.ProtectionProblem{Code: sysnet.ProblemRulesRejected,
				Message: "The policy was rejected: " + err.Error(), Hint: "The previous protection rules stay in force"}}
		}
		err = s.updateLocked(ctx, conn, *req.Policy, req.Op == OpEnable, by)
	case OpDisable:
		err = s.disableLocked(ctx, by)
	}
	status := s.statusLocked(ctx)
	resp := Response{ID: req.ID, Status: &status}
	if err != nil {
		p := problemOf(err, sysnet.ProblemPolicySync)
		resp.Error = &p
	}
	return resp
}

// check validates a client policy fully, including what only the PF
// backend accepts, before anything is saved.
func (s *Server) check(p protection.Policy) error {
	_, err := pf.Compile(p, pf.Env{OwnGroup: max(s.gid, 0)})
	return err
}

func problemOf(err error, code string) sysnet.ProtectionProblem {
	if problem, ok := errors.AsType[*protection.ProblemError](err); ok {
		return problem.Problem
	}
	return sysnet.ProtectionProblem{Code: code, Message: err.Error()}
}

func (s *Server) updateLocked(ctx context.Context, conn uint64, p protection.Policy, enable bool, by string) error {
	s.loadStateLocked()
	if s.stateErr != nil {
		return protection.Problem(sysnet.ProblemState, "Cannot read the saved protection state: "+s.stateErr.Error(), "")
	}
	if !enable && !s.state.Enabled {
		// Updates never turn protection on: a disabled kill switch stays
		// disabled until the user enables it again.
		s.runtime = &runtimePolicy{conn: conn, tunnels: p.Tunnels, own: p.OwnTraffic}
		return nil
	}
	next := s.state
	next.Enabled = true
	next.StartAtBoot = p.StartAtBoot
	next.Policy = p.Persistent().Normalize()
	if enable {
		next.ChangedBy = by
		s.modified, s.damaged = "", ""
	}
	if !s.stateExists || next.Policy.Fingerprint() != s.state.Policy.Fingerprint() || next.Enabled != s.state.Enabled ||
		next.StartAtBoot != s.state.StartAtBoot {
		next.UpdatedAt = s.cfg.Now().Unix()
		if err := SaveState(s.cfg.StateFile, next); err != nil {
			return protection.Problem(sysnet.ProblemState, "Cannot save the protection state: "+err.Error(), "Nothing was changed")
		}
		s.state, s.stateExists, s.stateErr = next, true, nil
	}
	s.runtime = &runtimePolicy{conn: conn, tunnels: p.Tunnels, own: p.OwnTraffic}
	s.reconcileLocked(ctx, "policy "+map[bool]string{true: "enabled", false: "updated"}[enable])
	if !s.effective {
		if s.applyErr != nil {
			return s.applyErr
		}
		return protection.Problem(sysnet.ProblemPolicySync, "Protection could not be verified after applying it", "")
	}
	return nil
}

// disableLocked saves the disabled state first, then removes the rules: a
// restart in between cannot bring protection back.
func (s *Server) disableLocked(ctx context.Context, by string) error {
	s.loadStateLocked()
	next := s.state
	if s.stateErr != nil {
		next = State{}
	}
	next.Enabled, next.ChangedBy, next.UpdatedAt = false, by, s.cfg.Now().Unix()
	if err := SaveState(s.cfg.StateFile, next); err != nil {
		return protection.Problem(sysnet.ProblemState, "Cannot save the disabled state, so protection was left on: "+err.Error(),
			"Try: sudo yuhaiin protection disable --recovery")
	}
	s.state, s.stateExists, s.stateErr = next, true, nil
	s.damaged = ""
	s.reconcileLocked(ctx, "disabled by "+by)
	return s.applyErr
}

func (s *Server) loadStateLocked() {
	st, exists, err := LoadState(s.cfg.StateFile)
	if errors.Is(err, ErrCorrupt) {
		// A damaged state fails closed: it is moved aside and replaced by
		// protection with only private networks allowed, until the user
		// enables or disables protection again.
		log.Error("network protection: saved state is damaged; blocking with only private networks allowed", "err", err)
		quarantine(s.cfg.StateFile)
		st = State{Enabled: true, StartAtBoot: true, ChangedBy: "damaged-state", UpdatedAt: s.cfg.Now().Unix(),
			Policy: protection.Policy{Mode: sysnet.ProtectionModeStandard, PrivateNetworks: policy.PrivateNetworks(), BypassNetworks: []netip.Prefix{}}}
		if serr := SaveState(s.cfg.StateFile, st); serr != nil {
			s.stateErr = errors.Join(err, serr)
			return
		}
		s.damaged = err.Error()
		exists, err = true, nil
	}
	if err == nil {
		s.state, s.stateExists = st, exists
	}
	s.stateErr = err
}

// reconcileLocked makes the operating system match the saved state. It is
// called on start, on every change and periodically, so it also repairs
// rules another program removed. s.mu is held.
func (s *Server) reconcileLocked(ctx context.Context, reason string) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	s.loadStateLocked()
	boot := s.bootID()
	s.waiting = false
	desired := s.state
	if s.stateErr != nil {
		// Unreadable (and not repairable): change nothing.
		s.applyErr = protection.Problem(sysnet.ProblemState, "Cannot read the saved protection state: "+s.stateErr.Error(), "")
		s.effective = s.checkEffective(ctx)
		return
	}
	if !desired.Enabled {
		s.applyErr = s.removeLocked(ctx)
		s.effective = false
		return
	}
	if !desired.StartAtBoot && desired.AppliedBoot != boot && s.runtime == nil {
		// Protection at startup is off: it returns when Yuhaiin connects.
		s.waiting, s.effective, s.applyErr = true, false, nil
		return
	}
	p := desired.Policy
	p.StartAtBoot = desired.StartAtBoot
	env := pf.Env{}
	if s.runtime != nil {
		p.Tunnels = s.presentTunnels(s.runtime.tunnels)
		if s.runtime.own && s.gid > 0 {
			p.OwnTraffic, env.OwnGroup = true, s.gid
		}
	}
	rs, err := pf.Compile(p, env)
	if err != nil {
		s.applyErr = protection.Problem(sysnet.ProblemRulesRejected, "The saved policy cannot be compiled: "+err.Error(), "")
		s.effective = s.checkEffective(ctx)
		return
	}
	e := s.cfg.Engine
	in := e.Inspect(ctx)
	s.applyErr = nil
	if !in.Conf.Filter || (in.RefKnown && !in.FilterRef) {
		if in.ConfKnown && in.Conf.Filter && !s.mayHeal() {
			s.applyErr = protection.Problem(sysnet.ProblemModified, "Another program keeps replacing the packet filter main ruleset without Yuhaiin's anchor",
				"Add `anchor \""+pf.Anchor+"/*\"` before the filter rules of that program's ruleset, or stop it")
		} else {
			if in.Conf.Filter {
				s.heals = append(s.heals, s.cfg.Now())
				s.modified = "the packet filter main ruleset was replaced; Yuhaiin's anchor was registered again"
			}
			if _, err := e.EnsureRegistered(ctx, true); err != nil {
				s.applyErr = err
			}
		}
	}
	loaded := pf.LoadedID(in.Rules)
	if loaded != rs.ID {
		if s.loadedID != "" && loaded != s.loadedID {
			s.modified = "Yuhaiin's protection rules were changed or removed by another program and were restored"
			log.Warn("network protection: rules changed outside Yuhaiin; restoring", "expected", s.loadedID, "found", loaded)
		}
		if err := e.Load(ctx, rs); err != nil {
			s.applyErr = errors.Join(s.applyErr, err)
		} else {
			s.loadedID = rs.ID
			log.Info("network protection rules loaded", "reason", reason, "id", rs.ID, "tunnels", len(p.Tunnels), "own", p.OwnTraffic, "bypass", len(p.BypassNetworks))
		}
	} else {
		s.loadedID = loaded
	}
	if desired.Token == "" || desired.TokenBoot != boot || (in.EnabledKnown && !in.Enabled) {
		if desired.Token == "" && in.EnabledKnown && in.Enabled {
			// Another program had the filter on before Yuhaiin.
			s.preexisting = true
		}
		token, err := e.Acquire(ctx)
		if err != nil {
			s.applyErr = errors.Join(s.applyErr, err)
		} else {
			if desired.Token != "" && desired.TokenBoot == boot {
				_ = e.Release(ctx, desired.Token)
			}
			desired.Token, desired.TokenBoot = token, boot
		}
	}
	desired.AppliedBoot = boot
	if desired.Token != s.state.Token || desired.TokenBoot != s.state.TokenBoot || desired.AppliedBoot != s.state.AppliedBoot {
		if err := SaveState(s.cfg.StateFile, desired); err != nil {
			s.applyErr = errors.Join(s.applyErr, protection.Problem(sysnet.ProblemState, "Cannot save the protection state: "+err.Error(), ""))
		} else {
			s.state = desired
		}
	}
	s.effective = s.checkEffectiveID(ctx, rs.ID)
	if s.effective {
		if s.applyErr == nil {
			s.updatedAt = s.cfg.Now().Unix()
		}
	} else if s.applyErr == nil {
		s.applyErr = protection.Problem(sysnet.ProblemPolicySync, "The packet filter does not enforce the protection rules after applying them", "")
	}
}

// mayHeal limits re-registering the main ruleset to three times in ten
// minutes.
func (s *Server) mayHeal() bool {
	cutoff := s.cfg.Now().Add(-10 * time.Minute)
	s.heals = slices.DeleteFunc(s.heals, func(t time.Time) bool { return t.Before(cutoff) })
	return len(s.heals) < 3
}

func (s *Server) presentTunnels(list []protection.Tunnel) []protection.Tunnel {
	ifaces, err := s.cfg.Interfaces()
	if err != nil {
		return nil
	}
	var out []protection.Tunnel
	for _, t := range list {
		if _, ok := iface.Find(ifaces, t.Name, ""); ok {
			out = append(out, t)
		}
	}
	return out
}

func (s *Server) checkEffective(ctx context.Context) bool {
	return s.checkEffectiveID(ctx, "")
}

// checkEffectiveID reads the OS state: protection is effective only when
// the filter is on, the main ruleset evaluates the anchor and the anchor
// holds Yuhaiin's block rule (with id, exactly that ruleset).
func (s *Server) checkEffectiveID(ctx context.Context, id string) bool {
	in := s.cfg.Engine.Inspect(ctx)
	loaded := pf.LoadedID(in.Rules)
	return in.EnabledKnown && in.Enabled && in.RefKnown && in.FilterRef && loaded != "" && (id == "" || loaded == id)
}

// removeLocked removes the kill switch rules and Yuhaiin's reference.
func (s *Server) removeLocked(ctx context.Context) error {
	e := s.cfg.Engine
	in := e.Inspect(ctx)
	var err error
	if !in.RulesKnown || len(in.Rules) != 0 {
		if ferr := e.Flush(ctx); ferr != nil {
			err = errors.Join(err, fmt.Errorf("remove protection rules: %w", ferr))
		}
	}
	s.loadedID = ""
	if s.state.Token != "" {
		if s.state.TokenBoot == s.bootID() {
			if rerr := e.Release(ctx, s.state.Token); rerr != nil {
				log.Warn("network protection: release PF reference", "err", rerr)
			}
		}
		next := s.state
		next.Token, next.TokenBoot = "", ""
		if serr := SaveState(s.cfg.StateFile, next); serr == nil {
			s.state = next
		} else {
			err = errors.Join(err, serr)
		}
	}
	return err
}

func (s *Server) bootID() string {
	if s.cfg.BootID == nil {
		return ""
	}
	return s.cfg.BootID()
}

// Status returns the current status (for in-process use).
func (s *Server) Status(ctx context.Context) sysnet.ProtectionStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.statusLocked(ctx)
}

// statusLocked reports the real OS state. s.mu is held.
func (s *Server) statusLocked(ctx context.Context) sysnet.ProtectionStatus {
	in := s.cfg.Engine.Inspect(ctx)
	st := Describe(in, s.state, s.stateErr)
	st.Service = "running"
	st.CheckedAt = s.cfg.Now().Unix()
	st.UpdatedAt = s.updatedAt
	loaded := pf.LoadedID(in.Rules)
	st.Effective = in.EnabledKnown && in.Enabled && in.RefKnown && in.FilterRef && loaded != ""
	if s.runtime != nil {
		present := s.presentTunnels(s.runtime.tunnels)
		if st.Effective {
			for _, t := range present {
				st.TunnelInterfaces = append(st.TunnelInterfaces, t.Name)
				st.TunnelIPv4, st.TunnelIPv6 = st.TunnelIPv4 || t.IPv4, st.TunnelIPv6 || t.IPv6
			}
		}
		st.OwnTraffic.Allowed = st.Effective && s.runtime.own && s.gid > 0
	}
	if s.gid > 0 {
		st.OwnTraffic.Group, st.OwnTraffic.GroupID = GroupName, s.gid
	}
	st.OwnTraffic.Method = "socket_group"
	if s.gidErr != nil {
		st.OwnTraffic.Reason = "the socket group could not be created: " + s.gidErr.Error()
	} else if s.runtime == nil {
		st.OwnTraffic.Reason = "Yuhaiin is not connected"
	} else if !s.runtime.own {
		st.OwnTraffic.Reason = "Yuhaiin's sockets do not carry the " + GroupName + " group (is Yuhaiin running as root?)"
	}
	if ifaces, err := s.cfg.Interfaces(); err != nil {
		st.Problems = append(st.Problems, sysnet.ProtectionProblem{Code: sysnet.ProblemInterfaces, Message: "Cannot list network interfaces: " + err.Error()})
	} else {
		for _, i := range ifaces {
			if i.Up && i.Type != iface.TypeLoopback && !slices.Contains(st.TunnelInterfaces, i.Name) {
				st.PhysicalInterfaces = append(st.PhysicalInterfaces, i.Name)
			}
		}
	}
	switch {
	case s.stateErr != nil:
		st.State = sysnet.ProtectionError
	case !s.state.Enabled:
		st.State = sysnet.ProtectionDisabled
		if loaded != "" {
			st.State = sysnet.ProtectionError
			st.Problems = append(st.Problems, sysnet.ProtectionProblem{Code: sysnet.ProblemModified, Message: "Protection is disabled but its rules are still loaded",
				Hint: "Run: sudo yuhaiin protection disable --recovery"})
		}
	case s.waiting:
		st.State = sysnet.ProtectionInitializing
		st.Problems = append(st.Problems, sysnet.ProtectionProblem{Code: sysnet.ProblemBootstrap,
			Message: "Protection at system startup is off; protection resumes when Yuhaiin starts"})
	case !st.Effective:
		st.State = sysnet.ProtectionError
	case s.runtime != nil && !st.OwnTraffic.Allowed:
		st.State = sysnet.ProtectionDegraded
		st.Problems = append(st.Problems, sysnet.ProtectionProblem{Code: sysnet.ProblemOwnTraffic,
			Message: "Yuhaiin's own connections are blocked: " + st.OwnTraffic.Reason, Hint: "Run Yuhaiin as the system service (sudo yuhaiin install)"})
	default:
		st.State = sysnet.ProtectionProtected
	}
	if s.applyErr != nil && s.state.Enabled {
		p := problemOf(s.applyErr, sysnet.ProblemPolicySync)
		st.Problems = append(st.Problems, p)
		st.Error = p.Message
		if st.State == sysnet.ProtectionProtected {
			st.State = sysnet.ProtectionDegraded
		}
	}
	if s.modified != "" && s.state.Enabled {
		st.Problems = append(st.Problems, sysnet.ProtectionProblem{Code: sysnet.ProblemModified, Message: s.modified})
	}
	if s.damaged != "" {
		st.Problems = append(st.Problems, sysnet.ProtectionProblem{Code: sysnet.ProblemState, Message: "The saved protection state was damaged (" + s.damaged + ")",
			Hint: "Protection blocks with only private networks allowed. Enable it again from Yuhaiin, or run: sudo yuhaiin protection disable --recovery"})
		if st.State == sysnet.ProtectionProtected {
			st.State = sysnet.ProtectionDegraded
		}
	}
	if s.preexisting && st.Effective {
		st.Problems = append(st.Problems, sysnet.ProtectionProblem{Code: sysnet.ProblemPreexistingState,
			Message: "The packet filter was already in use when protection started; connections opened before then may continue until they close"})
	}
	return st
}

// Describe turns an inspection and saved state into a status without the
// service's runtime knowledge. The command line uses it when the service is
// not running.
func Describe(in pf.Inspection, state State, stateErr error) sysnet.ProtectionStatus {
	st := protection.UnsupportedStatus()
	st.Supported, st.Backend, st.BackendName, st.Mode = true, "pf", "macOS Packet Filter", sysnet.ProtectionModeStandard
	st.Desired = sysnet.ProtectionSettings{Enabled: state.Enabled, StartAtBoot: state.StartAtBoot}
	st.Filter.Name = pf.ProtectionAnchor
	if in.EnabledKnown {
		st.Filter.Enabled = new(in.Enabled)
	}
	if in.RefKnown {
		st.Filter.Registered = new(in.FilterRef)
	}
	if in.ConfKnown {
		st.Filter.Persistent = new(in.Conf.Filter)
	}
	loaded := ""
	if in.RulesKnown {
		loaded = pf.LoadedID(in.Rules)
		st.Filter.Loaded = new(loaded != "")
	}
	if state.Token != "" && len(in.Tokens) > 0 {
		st.Filter.Reference = new(slices.Contains(in.Tokens, state.Token))
	} else if state.Token == "" && in.EnabledKnown {
		st.Filter.Reference = new(false)
	}
	if loaded != "" {
		st.PrivateNetworks = protection.PrefixStrings(state.Policy.PrivateNetworks, 1000)
		st.BypassNetworks = protection.PrefixStrings(state.Policy.BypassNetworks, 500)
		st.BypassCount = len(state.Policy.BypassNetworks)
		sum := pf.Summarize(in.Rules)
		if sum.HasBlock && sum.Blocked.HasPackets {
			st.Blocked = &sysnet.ProtectionCounters{Packets: sum.Blocked.Packets, Bytes: sum.Blocked.Bytes}
		}
		if sum.HasOwnStates {
			n := int(sum.OwnStates)
			st.OwnTraffic.Connections = &n
		}
	}
	st.Effective = in.EnabledKnown && in.Enabled && in.RefKnown && in.FilterRef && loaded != ""
	if stateErr != nil {
		st.Error = stateErr.Error()
		st.Problems = append(st.Problems, sysnet.ProtectionProblem{Code: sysnet.ProblemState, Message: stateErr.Error(),
			Hint: "Protection blocks with only private networks allowed. Enable it again from Yuhaiin, or run: sudo yuhaiin protection disable --recovery"})
	}
	for _, err := range in.Errors {
		st.Problems = append(st.Problems, sysnet.ProtectionProblem{Code: sysnet.ProblemPolicySync, Message: "Reading the packet filter state failed: " + err.Error()})
	}
	switch {
	case stateErr != nil:
		st.State = sysnet.ProtectionError
	case !state.Enabled && loaded == "":
		st.State = sysnet.ProtectionDisabled
	case !st.Effective:
		st.State = sysnet.ProtectionError
	default:
		st.State = sysnet.ProtectionProtected
	}
	return st
}
