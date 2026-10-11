package supervisor

// The Manager is the engine. It holds the set of live listeners, each running
// in its own goroutine, and reconciles them to the on-disk config via Apply
// (initial load + on SIGHUP-style reload), and to per-listener edits via the
// individual Rebuild / Stop methods the management API calls.
//
// Construction is pluggable for tests: Manager.ctor defaults to client.NewServer,
// and the supervisor's tests inject a fake that returns an in-memory Server so
// the lifecycle, locking, status, and reconciliation logic run under `go test`
// without ever needing a TUN. The actual veepin binary uses the real ctor.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xen0bit/veepin/client"
	"github.com/xen0bit/veepin/internal/hostnet"
	"github.com/xen0bit/veepin/internal/vlog"
)

// Constructor turns a ListenerConfig into a constructed (not yet listening)
// client.Server. The default realises to client.NewServer on the listener's
// protocol/options; tests pass a fake so the supervisor runs without privileges
// or sockets.
type Constructor func(protocol string, opts map[string]string) (client.Server, error)

// Status is the visible state of one listener. It is what the management API
// returns; Network is stringified so json.Marshal produces a self-describing
// field rather than the opaque *net.IPNet the Server interface exposes.
type Status struct {
	Name     string `json:"name"`
	Protocol string `json:"protocol"`
	State    string `json:"state"` // "running", "building", "stopped", "error", "disabled"
	TUNName  string `json:"tun,omitempty"`
	Gateway  string `json:"gateway,omitempty"`
	Network  string `json:"network,omitempty"`
	Error    string `json:"error,omitempty"`
	// No omitempty: it does nothing on a struct, so a zero Since serialised as
	// "0001-01-01T00:00:00Z" regardless and the tag only read as though it did
	// not. omitzero is the tag that would work, and the panel handles the zero
	// value fine, so this stays plain rather than changing the wire shape.
	Since time.Time `json:"since"`
}

// running is the live handle for one listener: the constructed server, the
// goroutine that owns it until Close returns, and the state the management API
// reads back.
//
// mu guards every field below it, without exception. That is stricter than the
// call graph makes it look, and deliberately so: Manager.Status releases
// Manager.mu before it reads a handle, so Manager.mu is NOT a second layer of
// protection over these fields the way it is over the listeners map. An earlier
// version wrote cfg/state/serveErr on the rebuild-failed path while holding only
// Manager.mu and raced Status for exactly that reason.
//
// done is also the generation marker. stopListener clears it, so a serve goroutine
// that returns late — after the 5s wait gave up, or after a rebuild already
// installed a new server — can tell that the state it is holding is stale and
// decline to publish it.
type running struct {
	mu       sync.Mutex
	cfg      ListenerConfig
	srv      client.Server
	state    string
	since    time.Time
	serveErr error
	done     chan struct{}

	// buildMu serializes stop/start on this handle. A rebuild is stop-then-start
	// and the whole sequence takes the lock, so two concurrent rebuilds (an API
	// restart racing a SIGHUP reconcile) cannot interleave a Close with a fresh
	// ListenAndServe on the same handle. Rebuild releases Manager.mu around the
	// rebuild so the "building" state is observable and a slow build does not
	// freeze every other listener's status read; buildMu is what makes that safe.
	buildMu sync.Mutex
}

// setState publishes a terminal build outcome (disabled, or error) on r.
func (r *running) setState(cfg ListenerConfig, state string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cfg = cfg
	r.srv = nil
	r.state = state
	r.serveErr = err
	r.since = time.Now()
}

// Manager owns a set of listeners and reconciles them to a config directory.
// Each listener lives in one goroutine; per-listener operations acquire that
// listener's mutex and the manager's outer mutex in that order, so a rebuild
// never races a teardown for the same name.
type Manager struct {
	dir  string
	ctor Constructor
	log  *vlog.Logger
	// run is the commander hostnet shells out through. Nil means the real
	// ip/iptables/sysctl; tests set it with SetCommander so the host-networking
	// half of a build is exercised without privileges, the same way ctor covers
	// the server half.
	run hostnet.Commander

	mu        sync.Mutex // guards listeners map and closed
	listeners map[string]*running
	// closed is latched by Close. Apply and Rebuild refuse afterwards, so a
	// mutation already in flight on an HTTP goroutine cannot rebuild the fleet
	// out from under a shutdown that has already torn it down.
	closed bool

	// abandoned counts listeners whose Close overran stopGrace and are still
	// holding their goroutine and TUN fd; abandonedTotal counts every one that
	// ever has.
	//
	// The pair is deliberate. The gauge answers "is something wedged right
	// now", which is what an operator wants; the counter answers "has this
	// happened", which is what survives a listener that eventually unblocks
	// and would otherwise erase the evidence. reap decrements the gauge and
	// never the counter.
	//
	// Atomics rather than fields under mu, and NOT as a micro-optimisation.
	// stopListenerLocked runs with Manager.mu held by Stop, Close and Apply, so
	// touching mu from the abandonment path deadlocks the manager -- the exact
	// failure this package exists to prevent, and one
	// TestStopDoesNotWedgeTheManager catches in ten seconds. reap has the same
	// constraint from the other direction: it must be able to record a
	// completion while a caller holds mu waiting on something else.
	abandoned      atomic.Int64
	abandonedTotal atomic.Uint64
}

// Abandoned reports how many listeners are currently abandoned -- Close overran
// stopGrace and has not returned since -- and how many ever have been.
//
// This is a leak made visible rather than a leak fixed. Each abandoned listener
// still holds a goroutine and a TUN fd until its own Close finally returns, and
// a fleet that restarts a genuinely wedged listener on a timer accumulates one
// of each per attempt. Before this pair existed it did so silently: the only
// trace was a log line nobody greps for. The real fix is for the blocking path
// to become interruptible, which lives in whichever protocol owns it.
func (m *Manager) Abandoned() (current int, total uint64) {
	return int(m.abandoned.Load()), m.abandonedTotal.Load()
}

// reap watches an abandoned teardown after stopListenerLocked has stopped
// waiting for it. If Close eventually returns, the goroutine and fd it was
// holding are released, so the gauge comes back down and the log says so --
// which is the difference between "wedged and stuck" and "wedged and slow", and
// an operator staring at a dashboard cannot tell them apart otherwise.
//
// It holds no locks while waiting, so a Close that never returns costs one
// parked goroutine and nothing else. That goroutine is itself part of the leak
// being counted; it is not free, and it is much cheaper than the pump and fd it
// is reporting on.
func (m *Manager) reap(name string, closed <-chan struct{}, started time.Time) {
	<-closed
	m.abandoned.Add(-1)
	m.log.Warnf("supervisor: %s: abandoned listener's Close finally returned after %s; "+
		"its goroutine and TUN fd are released", name, time.Since(started).Round(time.Millisecond))
}

// NewManager returns a Manager whose ctor is real if none is supplied.
func NewManager(dir string, logger *vlog.Logger, ctor Constructor) *Manager {
	if ctor == nil {
		// DefaultConstructor is the production path: client.NewServer.
		ctor = client.NewServer
	}
	if logger == nil {
		logger = vlog.Discard()
	}
	return &Manager{
		dir:       dir,
		ctor:      ctor,
		log:       logger,
		listeners: make(map[string]*running),
	}
}

// SetCommander replaces the external command runner the host-networking calls
// use. It exists for tests -- production leaves it unset, which means
// ip/iptables/sysctl via os/exec.
//
// Call it before Apply, and only then. It takes no lock deliberately: the
// readers (applyHostnet, teardownHostnet, and start by way of Rebuild) run with
// Manager.mu released, so locking only the writer would have made the field
// read as protected while protecting nothing -- which is worse than not locking
// it, because the next person to touch this would believe the guarantee.
// "Before Apply" is the real contract, and it is one a caller can keep.
func (m *Manager) SetCommander(run hostnet.Commander) {
	m.run = run
}

// applyHostnet installs a listener's host networking through whichever commander
// this Manager was given.
func (m *Manager) applyHostnet(name string, cfg hostnet.Config) error {
	if m.run == nil {
		return hostnet.Apply(name, cfg)
	}
	return hostnet.ApplyWithName(name, cfg, m.run)
}

// teardownHostnet is applyHostnet's inverse, through the same commander.
func (m *Manager) teardownHostnet(name string, cfg hostnet.Config) error {
	if m.run == nil {
		return hostnet.Teardown(name, cfg)
	}
	return hostnet.TeardownWithName(name, cfg, m.run)
}

// teardownHostnetState is the persisted-state form of teardownHostnet, used by
// stopListener so rules are removed for what Apply actually installed, not for
// whatever the listener's config now says.
func (m *Manager) teardownHostnetState(name string, st hostnet.State) error {
	if m.run == nil {
		return hostnet.TeardownState(name, st)
	}
	return hostnet.TeardownStateWithName(name, st, m.run)
}

// teardownHostnetByTag is the recovery form, used when no persisted state
// survives to say what was installed.
func (m *Manager) teardownHostnetByTag(name string) error {
	if m.run == nil {
		return hostnet.TeardownByTag(name)
	}
	return hostnet.TeardownByTagWithName(name, m.run)
}

// hostnetStatePath is where the supervisor persists what hostnet.Apply installed
// for one listener. Teardown reads it back because a listener's config may have
// been edited since (WAN dropped, address changed) and a kernel-assigned TUN
// name exists only in this record once the server that owned it is closed; a
// teardown re-derived from the config would remove nothing.
func hostnetStatePath(dir, name string) string {
	return filepath.Join(dir, "mgmt", "hostnet", name+".json")
}

// persistHostnetState records the host state Apply just installed, so a later
// stop/rebuild/delete can remove exactly that. Only reached for listeners with
// SetupNAT; a state with an empty WAN or Network installed no rules, and
// TeardownState treats it as a no-op, so the file lifecycle is uniform. Failure
// to persist is logged, not fatal -- the listener is up and serving either way.
//
// Written through a temp file, synced, and renamed, like every other config
// this daemon owns. os.WriteFile truncates in place, so a crash between
// truncate and write leaves valid-length garbage that loadHostnetState cannot
// parse, which drops teardown onto the tag-scan recovery path for no reason;
// and skipping the sync entirely leaves the same hazard one rename later, on
// filesystems whose rename is not ordered behind the data.
func (m *Manager) persistHostnetState(name string, st hostnet.State) {
	body, err := json.Marshal(st)
	if err != nil {
		m.log.Printf("supervisor: %s: persisting host state: %v", name, err)
		return
	}
	path := hostnetStatePath(m.dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		m.log.Printf("supervisor: %s: creating host-state dir: %v", name, err)
		return
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		m.log.Printf("supervisor: %s: writing host state: %v", name, err)
		return
	}
	// The temp file is never kept past its rename; if anything below fails, the
	// only harm is a stale temp that a later persist truncates again.
	if _, err := f.Write(body); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		m.log.Printf("supervisor: %s: writing host state: %v", name, err)
		return
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		m.log.Printf("supervisor: %s: syncing host state: %v", name, err)
		return
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		m.log.Printf("supervisor: %s: closing host state: %v", name, err)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		m.log.Printf("supervisor: %s: installing host state: %v", name, err)
	}
}

// loadHostnetState reads back what Apply installed for name, or nil when nothing
// was persisted -- a listener that predates this feature, or one that never
// installed host state.
func (m *Manager) loadHostnetState(name string) *hostnet.State {
	body, err := os.ReadFile(hostnetStatePath(m.dir, name))
	if err != nil {
		return nil
	}
	var st hostnet.State
	if err := json.Unmarshal(body, &st); err != nil {
		m.log.Printf("supervisor: %s: host state unreadable; tearing down from config: %v", name, err)
		return nil
	}
	return &st
}

// removeHostnetState drops the persisted record once teardown has consumed it.
func (m *Manager) removeHostnetState(name string) {
	_ = os.Remove(hostnetStatePath(m.dir, name))
}

// Apply reconciles the live set to the directory. New configs are built;
// removed configs are torn down; changed configs are cold-rebuilt; disabled
// configs are stopped; untouched configs keep running -- exactly the set
// difference against the on-disk state.
//
// The whole diff is computed under Manager.mu, then each per-listener action
// happens via methods that re-acquire the lock -- so a long build does not
// hold the manager lock for other listeners' status reads.
//
// A listener that will not start is reported but does not abort the pass. Apply
// returns every such failure joined together, and each failed listener stays
// tracked in "error" state carrying its reason, so it appears in the API and the
// next Apply retries it. Returning on the first failure -- which this used to do
// -- meant one listener with a bad option took the whole fleet down at startup,
// including the listeners that had already come up in the same pass.
//
// An unreadable config directory is different, and still fatal: LoadDir reports
// it before any listener has been touched.
func (m *Manager) Apply() error {
	cfgs, err := LoadDir(m.dir)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return errClosed
	}

	var errs []error

	// 1. Stop listeners that are gone or now disabled. A disabled one stays in
	// the map, stopped; only a listener whose file has disappeared is removed.
	//
	// Deleting the disabled ones meant step 2 rebuilt them on the very next
	// pass, because they were no longer present -- so every SIGHUP tore down
	// and reconstructed each disabled listener, ran its hostnet teardown (a
	// full `iptables -S` scan, for rules it never installed), and reset its
	// Status.Since, which is why "disabled since" was always "just now".
	for name, r := range m.listeners {
		cfg, ok := cfgs[name]
		if !ok {
			m.stopListener(r)
			delete(m.listeners, name)
			continue
		}
		if !cfg.Enabled {
			m.stopListener(r)
			r.mu.Lock()
			r.cfg = cfg
			r.state = "disabled"
			r.mu.Unlock()
			continue
		}
		if configChanged(r.cfg, cfg) {
			if err := m.rebuildLocked(r, cfg); err != nil {
				errs = append(errs, fmt.Errorf("rebuilding %q: %w", name, err))
			}
		}
	}

	// 2. Build new listeners. We do not gate on KnownProtocol here: the ctor
	// (client.NewServer by default) is the source of truth for which protocols
	// exist, and rejects an unknown name with ErrUnknownProtocol. Testing the
	// gate here would need the registry to know the protocol, which makes a
	// unit test import every facade just to construct a manager.
	for name, cfg := range cfgs {
		if _, exists := m.listeners[name]; exists {
			continue
		}
		r, err := m.build(cfg)
		if err != nil {
			errs = append(errs, fmt.Errorf("building %q: %w", name, err))
		}
		// Tracked either way: start published the failure on the handle, and a
		// listener that is listed as broken is more use to an operator than one
		// that silently does not exist.
		m.listeners[name] = r
	}
	if len(errs) > 0 {
		return fmt.Errorf("supervisor: %w", errors.Join(errs...))
	}
	return nil
}

// configChanged reports whether rebuilding is required, comparing only fields
// that affect the constructed Server or its host networking. ListenPort etc.
// live inside Options, so they are part of the diff automatically.
func configChanged(a, b ListenerConfig) bool {
	if a.Protocol != b.Protocol || a.SetupNAT != b.SetupNAT || a.WAN != b.WAN || a.Enabled != b.Enabled {
		return true
	}
	if len(a.Options) != len(b.Options) {
		return true
	}
	for k, av := range a.Options {
		if b.Options[k] != av {
			return true
		}
	}
	return false
}

// statusOf reads r's state under r.mu and returns it as a Status. The caller may
// or may not hold Manager.mu -- r.mu is the only lock that protects these fields,
// so this is safe either way.
func statusOf(r *running) Status {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := Status{
		Name:     r.cfg.Name,
		Protocol: r.cfg.Protocol,
		State:    r.state,
		Since:    r.since,
		Error:    "",
	}
	if r.serveErr != nil {
		s.Error = r.serveErr.Error()
	}
	if r.srv != nil {
		s.TUNName = r.srv.TUNName()
		if g := r.srv.Gateway(); g != nil {
			s.Gateway = g.String()
		}
		if n := r.srv.Network(); n != nil {
			s.Network = n.String()
		}
	}
	return s
}

// Status returns the visible state of one listener, or a zero Status with
// State="unknown" if no such listener is tracked. The management API reports
// this verbatim.
func (m *Manager) Status(name string) Status {
	m.mu.Lock()
	r, ok := m.listeners[name]
	m.mu.Unlock()
	if !ok {
		return Status{Name: name, State: "unknown"}
	}
	return statusOf(r)
}

// All returns the status of every tracked listener, sorted by name. The
// management API's GET /api/listeners renders this.
func (m *Manager) All() []Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Status, 0, len(m.listeners))
	// Sorted by name for stable API output; statusOf is the per-listener
	// section that acquires the listener mutex.
	byName := make([]string, 0, len(m.listeners))
	for n := range m.listeners {
		byName = append(byName, n)
	}
	slices.Sort(byName)
	for _, n := range byName {
		out = append(out, statusOf(m.listeners[n]))
	}
	return out
}

// Rebuild forces the named listener back to build then ListenAndServe, the
// operation triggered by a config edit. Safe to call against a stopped or
// errored listener -- it tears down what is there, if anything, and rebuilds.
//
// Manager.mu is released for the rebuild itself: holding it across a slow
// construction would freeze every other listener's status read and, worse,
// make the "building" state unobservable through the API (Status needs the
// lock to look the handle up). buildMu on the handle serializes the rebuild
// against a concurrent SIGHUP reconcile, and the handle is put back if a
// concurrent Apply stopped and removed it while we were building.
func (m *Manager) Rebuild(name string) error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return errClosed
	}
	r, ok := m.listeners[name]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("supervisor: no listener named %q", name)
	}
	cfgs, err := LoadDir(m.dir)
	if err != nil {
		m.mu.Unlock()
		return err
	}
	cfg, ok := cfgs[name]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("supervisor: %q has no on-disk config; DeleteListenerFile removed it", name)
	}
	m.mu.Unlock()
	err = m.rebuildLocked(r, cfg)
	// A Stop, a Close, or a SIGHUP reconcile may have dropped this listener from
	// the map while we were rebuilding. That removal is the later decision and
	// it wins: tear down whatever the rebuild left behind rather than putting
	// the handle back.
	//
	// Re-adding it was wrong in the interleaving that actually happens. Stop,
	// Close and Apply all block on buildMu until the rebuild finishes, so the
	// removal lands *after* the new server is up and closes it -- and the re-add
	// then resurrected an already-dead entry, leaving a listener whose config
	// file was deleted still tracked and Close returning with a non-empty map.
	//
	// Tearing down is also the right answer in the other order, where the
	// removal landed before start() and the server we just built is genuinely
	// running untracked: this is the only thing that stops it. stopListener is a
	// no-op on a handle the remover already closed, so both cases are covered by
	// the same call. It runs without Manager.mu, like the rebuild above, so a
	// slow Close cannot freeze the fleet.
	// By IDENTITY, not by name. A Stop followed by an Apply can put a DIFFERENT
	// handle under this name, and a presence-by-name check then reads as "still
	// tracked" -- leaving the server this rebuild just built neither torn down
	// nor reachable, running untracked until the process exits.
	m.mu.Lock()
	still := m.listeners[name] == r
	m.mu.Unlock()
	if !still {
		m.stopListener(r)
	}
	return err
}

// Stop tears down a listener and drops it from the live set. Its config file
// remains on disk; rebuild from a later Apply or a management API call picks
// it back up.
func (m *Manager) Stop(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.listeners[name]
	if !ok {
		return fmt.Errorf("supervisor: no listener named %q", name)
	}
	m.stopListener(r)
	delete(m.listeners, name)
	return nil
}

// Close tears every listener down. Called on supervisor shutdown. An
// individual listener returning net.ErrClosed is the expected outcome of
// being Close()d here, not an error to surface; Close reports an error only if
// a listener's serve goroutine recorded a non-shutdown failure.
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Latched before anything is torn down, so a concurrent Apply or Rebuild
	// refuses rather than rebuilding the fleet from disk behind us.
	//
	// cmd/veepin calls Close on SIGTERM while the management API's create
	// handler can be inside Apply on an HTTP goroutine. Without the flag, Close
	// emptied the map and that in-flight Apply then reopened every TUN, rebound
	// every socket and reinstalled every iptables rule -- after the process had
	// decided to exit, and with nothing left to tear any of it down again.
	m.closed = true
	var firstErr error
	for name, r := range m.listeners {
		m.stopListener(r)
		delete(m.listeners, name)
		// serveErr under r.mu like every other field on the handle. stopListener
		// waits for the serve goroutine before returning, so this read is
		// already ordered -- and being ordered by a wait somewhere else is
		// exactly the kind of thing a refactor moves. The package README says
		// every field, without exception; this was the exception.
		r.mu.Lock()
		serveErr := r.serveErr
		r.mu.Unlock()
		if serveErr != nil && !errors.Is(serveErr, net.ErrClosed) && firstErr == nil {
			firstErr = serveErr
		}
	}
	return firstErr
}

// errClosed is what Apply and Rebuild answer after Close.
var errClosed = errors.New("supervisor: manager is closed")

// PeerAvailability says why a peer list is or is not available, which used to
// be one bool covering three different answers.
type PeerAvailability int

const (
	// PeersNoSuchListener: nothing by that name is tracked.
	PeersNoSuchListener PeerAvailability = iota
	// PeersNotRunning: the listener exists but has no server handle -- it is
	// stopped, disabled, or in error. Collapsing this into "no such listener"
	// made the panel's expanded detail for a listener in error state report
	// that the listener did not exist, while the status half of the same view
	// answered 200. That row is exactly the one an operator opens.
	PeersNotRunning
	// PeersUnsupported: running, but the protocol implements no PeerDescriber.
	// The caller renders "no peer feature", not "no peers".
	PeersUnsupported
	// PeersOK: the returned slice is the live peer list.
	PeersOK
)

// Peers returns the live peer list for a running listener whose protocol
// implements client.PeerDescriber, and says which of the four cases applies.
//
// The PeerDescriber call runs while holding r.mu. That ordering is the point:
// stopListener clears r.srv and spawns srv.Close while holding r.mu, so a
// concurrent rebuild or stop blocks on r.mu before it can tear the server down
// underneath this call. Reading the live server through Server() and calling
// Peers() afterward released r.mu first, which left the raw handle open to a
// use-after-close exactly when a panel poll raced a rekey or a rebuild.
//
// m.mu is released before the callback. Holding it across a protocol's Peers()
// -- which may take that protocol's own lock, contended by a rekey -- froze
// every Status, All, Apply and Stop in the process for the duration, which is
// the opposite of the argument the rest of this file is built on. r.mu alone
// gives the use-after-close protection above; the manager lock was only ever
// needed to look the handle up.
func (m *Manager) Peers(name string) ([]client.PeerInfo, PeerAvailability) {
	m.mu.Lock()
	r, ok := m.listeners[name]
	m.mu.Unlock()
	if !ok {
		return nil, PeersNoSuchListener
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.srv == nil {
		return nil, PeersNotRunning
	}
	pd, ok := r.srv.(client.PeerDescriber)
	if !ok {
		return nil, PeersUnsupported
	}
	return pd.Peers(), PeersOK
}

// build allocates a fresh handle and starts it. The handle is returned whether
// the start succeeded or not -- on failure it carries the "error" state and the
// reason -- so a caller can track a listener that would not come up. Called
// under Manager.mu; the goroutine start launches does not need the manager lock,
// only r.mu, so a long-lived Server never pins the manager.
func (m *Manager) build(cfg ListenerConfig) (*running, error) {
	r := &running{}
	return r, m.start(r, cfg)
}

// start constructs the listener's server, installs its host networking, and
// launches the serve goroutine against r. It publishes the outcome on r whether
// it succeeds or fails, so a caller that keeps the handle around always has a
// state and an error to report; the error is also returned for callers that
// want to propagate it.
//
// Called with r.mu NOT held: construction can block on a TUN open and a syscall
// or two of iptables, and holding the status lock across that would stall the
// management API's reads for the duration.
func (m *Manager) start(r *running, cfg ListenerConfig) error {
	if !cfg.Enabled {
		// Said out loud. A listener that is present, valid, and deliberately not
		// running is indistinguishable at a glance from one that failed to start,
		// and the operator's next question is always which of the two it is.
		m.log.Printf("supervisor: %s/%s: disabled by config; not started", cfg.Name, cfg.Protocol)
		r.setState(cfg, "disabled", nil)
		return nil
	}
	// Published before construction so a slow build is visible rather than a
	// stale "running" (or a pre-rebuild "building") that makes the panel look
	// frozen. Construction can block on a TUN open and a syscall or two of
	// iptables, which is exactly the moment an operator staring at the panel
	// wants to know something is happening.
	r.mu.Lock()
	r.state = "building"
	r.since = time.Now()
	r.mu.Unlock()
	srv, err := m.ctor(cfg.Protocol, cfg.Options)
	if err != nil {
		err = fmt.Errorf("supervisor: constructing %s server: %w", cfg.Protocol, err)
		r.setState(cfg, "error", err)
		return err
	}
	if cfg.SetupNAT {
		hn := hostnet.Config{
			TUNName: srv.TUNName(),
			Gateway: srv.Gateway(),
			Network: srv.Network(),
			WAN:     cfg.WAN,
		}
		// The IPv6 half, for the one protocol that assigns v6 inside the
		// tunnel. Optional rather than part of client.Server, so a facade
		// without a v6 pool answers nothing rather than answering nil.
		if ds, ok := srv.(client.DualStackServer); ok {
			hn.Gateway6, hn.Network6 = ds.Gateway6(), ds.Network6()
		}
		switch aerr := m.applyHostnet(cfg.Name, hn); {
		case aerr == nil:
			m.persistHostnetState(cfg.Name, hn.State())
		case errors.Is(aerr, hostnet.ErrNoWAN), errors.Is(aerr, hostnet.ErrNoIPv6):
			// Both mean "the listener is serving, but does not reach
			// everything": ErrNoWAN that it is addressed, up and forwarding
			// with no route off the host, ErrNoIPv6 that its v4 half is
			// complete and the host cannot do the v6 half. Each is a
			// misconfiguration worth saying out loud, not a reason to refuse to
			// serve -- and certainly not a reason to take the rest of the fleet
			// down, which is what returning here used to do at startup.
			//
			// ErrNoIPv6 especially: ikev2's v6 pool is on by default, so a host
			// without ip6tables would otherwise fail every ikev2 listener over
			// a capability nobody asked for.
			//
			// The state is still persisted, so a later rebuild that adds a WAN
			// tears the rules it then installs down correctly.
			for _, line := range strings.Split(aerr.Error(), "\n") {
				m.log.Printf("supervisor: %s: %s", cfg.Name, line)
			}
			m.persistHostnetState(cfg.Name, hn.State())
		default:
			// Apply may have installed part of its state before failing. Take it
			// back out so a retry starts from a clean host rather than from
			// whatever half of the rule set landed.
			_ = m.teardownHostnet(cfg.Name, hn)
			_ = srv.Close()
			aerr = fmt.Errorf("supervisor: host networking: %w", aerr)
			r.setState(cfg, "error", aerr)
			return aerr
		}
	}
	done := make(chan struct{})
	r.mu.Lock()
	r.cfg, r.srv, r.state, r.since, r.serveErr, r.done =
		cfg, srv, "running", time.Now(), nil, done
	r.mu.Unlock()
	// srv and done are passed by value rather than re-read from r: by the time
	// the goroutine runs, a Stop may already have cleared both, and this
	// generation of the goroutine owns this generation's server.
	go serve(r, m.log, srv, done)
	return nil
}

// rebuildLocked is the per-listener cold rebuild: stop, construct new, start.
// It re-uses the running handle so external references to the listener (a status
// read that captured the pointer) keep referring to the same *running. On
// failure start leaves r in "error" state with the reason, so the next Apply
// retries it and the management API reports why.
//
// Called with Manager.mu held (Apply) or not (Rebuild); buildMu serializes the
// two so a SIGHUP reconcile and an API restart cannot rebuild the same handle
// concurrently.
func (m *Manager) rebuildLocked(r *running, cfg ListenerConfig) error {
	r.buildMu.Lock()
	defer r.buildMu.Unlock()
	// Published before the stop so the whole stop-then-start sequence reads as
	// one "building" phase to the panel. Without this the listener flashes
	// "stopped" between the two halves, and a rebuild that takes a moment looks
	// like the listener was taken down rather than being reconfigured.
	r.mu.Lock()
	r.state = "building"
	r.since = time.Now()
	r.mu.Unlock()
	m.stopListenerLocked(r)
	return m.start(r, cfg)
}

// stopGrace bounds how long a single listener may take to shut down before the
// supervisor stops waiting for it. It covers Close and the serve goroutine's
// exit together, so one listener's teardown cannot exceed it.
const stopGrace = 5 * time.Second

// stopListener closes the listener's server and waits for the goroutine to exit,
// then tears down any host-networking rules it owned. It acquires buildMu and
// r.mu itself. rebuildLocked calls stopListenerLocked directly while holding
// buildMu, so the whole stop-then-start stays one critical section.
//
// It was called stopLocked, which named a lock it does not take and does not
// require: Stop, Close and Apply call it holding Manager.mu, and Rebuild calls
// it having released Manager.mu deliberately, so a slow Close cannot freeze the
// fleet. A name asserting an invariant that half the call sites break is worse
// than no name at all -- the whole -Locked convention stops meaning anything.
// The paragraph below about Manager.mu describes the callers that do hold it.
//
// Both waits are bounded, and Close is called on a goroutine rather than inline,
// because Close can block. The once-central cause is fixed: dataplane's TUN fd
// is held non-blocking and polled against a wake eventfd, so a Close waiting on
// its packet pump unblocks instead of hanging on an idle tunnel. But Close can
// still stall on any other blocking path a protocol owns (a wedged control
// connection, a peer that never answers), and this package's job is that one
// listener can never freeze the fleet.
//
// That is invisible to `veepin serve <proto>`: it calls Close and exits, and the
// kernel cleans up. It is not invisible here. stopListener runs under Manager.mu,
// so an unbounded Close would freeze every Status, Apply, and Rebuild in the
// fleet behind it -- one listener wedging the entire management plane, which is
// the failure this whole package exists to avoid. Bounded, the listener is
// abandoned with a log line and the rest of the fleet keeps serving.
//
// Abandoning used to leak the pump goroutine and its TUN fd until that
// listener's Close finally returned, or until the process exited if it never
// did -- so a fleet restarting a wedged listener on a timer accumulated one of
// each per attempt. Two things changed that, and they are different in kind.
//
// The leak itself is closed by client.AbandonableServer. Every server here owns
// a TUN, dataplane holds that TUN non-blocking and polls it against a wake
// eventfd, and closing it unparks the pump's read -- so a listener whose Close
// is wedged can still have its descriptor taken away from underneath it, and the
// goroutine follows the fd out. Abandon takes no lock the wedged Close could be
// holding and waits for nothing, which is the whole reason it is not just Close
// called twice. What stays abandoned is state, not resources: sessions are not
// told, nothing is flushed, and the wedged Close is still wedged.
//
// The cost of that is made visible rather than assumed away. Manager.Abandoned
// reports a gauge and a cumulative counter, /api/metrics exports both, and reap
// keeps watching so a Close that eventually returns brings the gauge back down.
// A server that does not implement Abandon -- none in this tree, but the
// interface is optional for implementations outside it -- still leaks, and the
// log line says which case it was.
func (m *Manager) stopListener(r *running) {
	r.buildMu.Lock()
	defer r.buildMu.Unlock()
	m.stopListenerLocked(r)
}

// stopListenerLocked is the teardown itself. Callers must hold r.buildMu.
func (m *Manager) stopListenerLocked(r *running) {
	r.mu.Lock()
	srv, done, cfg := r.srv, r.done, r.cfg
	r.srv = nil
	// Clearing done retires this generation: a serve goroutine that returns
	// after this point finds r.done no longer its own and leaves the state
	// below alone.
	r.done = nil
	if r.state != "building" {
		// A rebuild pre-sets "building" and then calls this; keeping it means
		// the whole stop-then-start sequence reads as one "building" phase
		// instead of flashing "stopped" during the (possibly slow) Close. Every
		// other caller is a real stop, where "stopped" is the truth.
		r.state = "stopped"
	}
	r.since = time.Now()
	r.mu.Unlock()

	// One deadline for the whole teardown, shared by both waits below.
	deadline := time.After(stopGrace)
	var abandoned bool
	if srv != nil {
		closed := make(chan struct{})
		go func() {
			defer close(closed)
			_ = srv.Close()
		}()
		select {
		case <-closed:
		case <-deadline:
			abandoned = true
			current := m.abandoned.Add(1)
			total := m.abandonedTotal.Add(1)
			// Take the descriptors back before anything else. This is what
			// keeps abandonment from costing a goroutine and an fd for the
			// life of the process; see client.AbandonableServer.
			released := "its packet pump and TUN fd were released"
			if a, ok := srv.(client.AbandonableServer); ok {
				a.Abandon()
			} else {
				released = "it does not implement client.AbandonableServer, so its " +
					"packet pump goroutine and TUN fd are leaked until Close returns"
			}
			m.log.Warnf("supervisor: %s: Close did not return within %s; abandoning the listener "+
				"(%s). %d listener(s) abandoned now, %d since start -- see Manager.Abandoned",
				cfg.Name, stopGrace, released, current, total)
			go m.reap(cfg.Name, closed, time.Now())
		}
	}
	// No point waiting on the serve goroutine if Close has not even returned:
	// ListenAndServe cannot unblock before the thing it is serving is closed.
	if done != nil && !abandoned {
		select {
		case <-done:
		case <-deadline:
			m.log.Printf("supervisor: %s: serve goroutine still running after %s; carrying on",
				cfg.Name, stopGrace)
		}
	}
	// Host-state teardown for the listener's own rules; layer-2 / no-WAN
	// configs are a no-op in hostnet.Teardown, so it is safe to call
	// unconditionally.
	if cfg.SetupNAT {
		// Teardown from the persisted State, not from the current config: it
		// records the TUNName/Gateway/Network/WAN that Apply actually used,
		// where the config may have been edited since (WAN dropped) or never
		// named the interface (kernel-assigned tunN). An earlier version
		// re-derived a Config here with a nil Network, which made hostnet's
		// Teardown a silent no-op and left every tagged rule behind on
		// rebuild and delete.
		if st := m.loadHostnetState(cfg.Name); st != nil {
			_ = m.teardownHostnetState(cfg.Name, *st)
		} else {
			// No persisted record: a listener that predates this feature, or a
			// state file lost to a crash mid-write. Fall back to deleting by
			// the comment tag every rule Apply installs carries.
			//
			// The previous fallback re-derived a hostnet.Config here with a nil
			// Network, whose State() has an empty Network, which TeardownState
			// treats as "nothing rule-shaped was installed" and returns from
			// immediately. So the branch reached only in the case that leaks
			// rules was itself guaranteed to remove nothing -- the very bug the
			// persisted state was added to fix, preserved as a no-op under a
			// comment claiming it worked.
			if err := m.teardownHostnetByTag(cfg.Name); err != nil {
				m.log.Printf("supervisor: %s: tagged host-state teardown: %v", cfg.Name, err)
			}
		}
		m.removeHostnetState(cfg.Name)
	}
}

// serve is the goroutine that owns one listener's ListenAndServe. It records the
// result and signals completion via a deferred close(done) so stopListener can
// wait deterministically.
//
// srv and done are parameters, not reads off r, because this goroutine belongs
// to one generation of the listener: a rebuild installs a new server and a new
// done channel on the same handle. Publishing the result is gated on r.done
// still being this generation's channel, so a goroutine that returns after its
// server was replaced (or after stopListener gave up waiting) cannot overwrite the
// live listener's state with its own stale outcome.
func serve(r *running, logger *vlog.Logger, srv client.Server, done chan struct{}) {
	defer close(done)
	err := srv.ListenAndServe()

	r.mu.Lock()
	current := r.done == done
	if current {
		r.serveErr = err
		if err != nil && !errors.Is(err, net.ErrClosed) {
			r.state = "error"
		} else {
			r.state = "stopped"
		}
		r.since = time.Now()
	}
	name, protocol := r.cfg.Name, r.cfg.Protocol
	r.mu.Unlock()

	if err != nil && !errors.Is(err, net.ErrClosed) {
		logger.Printf("supervisor: %s/%s: %v", name, protocol, err)
	}
}
