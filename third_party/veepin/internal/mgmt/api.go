// Package mgmt is the supervisor's management plane: a small REST API for the
// listener directory that uses the supervisor.Manager as its data backend.
//
// It is stdlib-only by design: the strict-dependency contract (golang.org/x/*
// and nothing else at runtime) forbids a router library, so net/http.ServeMux
// pattern matching is enough for the surface below. The same contract forbids
// a logging library: a single *vlog.Logger writes a line per request.
//
// Auth is a bearer token generated on first run and stored at <config>/mgmt/token
// mode 0600 root-only, the same filesystem-protection posture the protocol
// facades' PEM and key files already rely on. The token is compared with
// crypto/subtle.ConstantTimeCompare.
//
// Secrets at rest in a ListenerConfig's Options map (private keys, PSKs,
// passphrases) are redacted on read by querying each protocol's
// client.ServerOptsFor metadata for Secret=true fields. Redaction replaces the
// value with the literal "<redacted>"; a PATCH that submits "<redacted>" for a
// secret key preserves the on-disk value rather than overwriting it with the
// placeholder, so a GET-then-PATCH round trip does not destroy the key.
package mgmt

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xen0bit/veepin/client"
	"github.com/xen0bit/veepin/internal/confstore"
	"github.com/xen0bit/veepin/internal/keygen"
	"github.com/xen0bit/veepin/internal/supervisor"
	"github.com/xen0bit/veepin/internal/vlog"
	"github.com/xen0bit/veepin/wireguard"
)

// redacted is the package-local spelling of client.Redacted, used often enough
// here to earn the short name. Sending it back on a PATCH means "leave
// unchanged"; sending it on a POST is refused, because there is nothing to
// leave. client.Redacted's own doc says why the value cannot collide with a
// real one.
const redacted = client.Redacted

// tokenName is the mgmt-bearer-token file name within the config dir.
const tokenName = "token"

// ManagerBackend is the supervisor surface the management API uses. The real
// *supervisor.Manager implements it; tests pass a fake so the HTTP layer runs
// in plain `go test` with no TUNs or sockets.
type ManagerBackend interface {
	Apply() error
	All() []supervisor.Status
	Status(name string) supervisor.Status
	Rebuild(name string) error
	Stop(name string) error
	Close() error
	Peers(name string) ([]client.PeerInfo, supervisor.PeerAvailability)
}

// Option adjusts a Server before its routes are wired. NewServer takes none,
// leaving every field at its default (notably no profile directory, which
// disables the /api/profiles endpoints).
type Option func(*Server)

// WithProfileDir points the /api/profiles endpoints at a directory of client
// connection profiles (the supervisor's -profiles flag). The API writes them
// with the same strict, atomic, mode-0600 confstore machinery the listener
// directory uses. Without it the profile endpoints answer 404.
func WithProfileDir(dir string) Option {
	return func(s *Server) { s.profiles = dir }
}

// WithLogRing attaches the supervisor's shared log ring to the API server so
// GET /api/logs can serve it. Without it the endpoint answers 404, which is the
// right default: a caller that never built a ring has no log to serve.
func WithLogRing(lr *LogRing) Option {
	return func(s *Server) { s.logs = lr }
}

// Server is the management HTTP server.
type Server struct {
	mgr   ManagerBackend
	dir   string
	token []byte
	log   *vlog.Logger
	mux   *http.ServeMux

	// audit is the bounded, in-memory mutation log (see audit.go). Every
	// create/patch/delete/restart records into it; GET /api/audit reads it.
	audit *auditLog

	// mutate serializes every read-modify-write of a listener file. Each of
	// those handlers reads the config, changes it, writes it back and rebuilds,
	// which is a lost update if two run at once: two concurrent client-config
	// calls on one WireGuard listener each read the same peer array, each
	// allocate the same tunnel address, and the second write silently discards
	// the first peer -- leaving a client holding a private key the server has
	// never heard of.
	//
	// One lock for the whole directory rather than one per listener: these are
	// operator actions at human rates, the critical sections include a cold
	// rebuild anyway, and a per-listener map is state to reap. Reads (list, get,
	// peers, audit) do not take it; they tolerate seeing either side of a write.
	mutate sync.Mutex

	// profiles is the on-disk profile directory, or "" when the supervisor did
	// not configure one (the /api/profiles endpoints then answer 404).
	profiles string

	// logs is the supervisor's shared log ring (see logring.go), or nil when
	// no ring was attached. GET /api/logs answers 404 without one.
	logs *LogRing

	// startedAt is the supervisor uptime start the health endpoint reports.
	startedAt atomic.Int64
}

// NewServer prepares the management plane for the given config dir: it reads
// or mints the bearer token, then wires routes under /api/. The Manager is the
// running-supervisor backend; dir is the on-disk config root that the POST/
// PATCH/DELETE endpoints persist to. NewServer is the canonical place the token
// is generated; it writes the token file once and reads it thereafter, so the
// operator can extract it from disk if the once-only log line was missed.
func NewServer(dir string, mgr ManagerBackend, logger *vlog.Logger, opts ...Option) (*Server, error) {
	if dir == "" {
		return nil, errors.New("mgmt: config dir is required")
	}
	if mgr == nil {
		return nil, errors.New("mgmt: supervisor manager is required")
	}
	if err := os.MkdirAll(filepath.Join(dir, "mgmt"), 0o700); err != nil {
		return nil, fmt.Errorf("mgmt: creating mgmt dir: %w", err)
	}
	tokenPath := filepath.Join(dir, "mgmt", tokenName)
	token, fresh, err := bootToken(tokenPath)
	if err != nil {
		return nil, fmt.Errorf("mgmt: token boot: %w", err)
	}
	if logger == nil {
		logger = vlog.Discard()
	}
	s := &Server{
		mgr:   mgr,
		dir:   dir,
		token: token,
		log:   logger,
		mux:   http.NewServeMux(),
		audit: newAuditLog(),
	}
	for _, opt := range opts {
		opt(s)
	}
	// Stamped here rather than on a serve call. The supervisor mounts Handler on
	// its own mux (it also serves the panel at the root) and never went through
	// a Start method, so an uptime the serve path was supposed to set stayed
	// zero and /api/health reported the whole Unix epoch as uptime.
	s.startedAt.Store(time.Now().Unix())
	if fresh {
		logger.Printf("mgmt: no bearer token found; generated one at %s (mode 0600)", tokenPath)
	}

	s.mux.HandleFunc("GET /api/health", s.handleHealth)
	s.mux.HandleFunc("GET /api/protocols", s.handleProtocols)
	s.mux.HandleFunc("GET /api/listeners", s.handleListListeners)
	s.mux.HandleFunc("POST /api/listeners", s.handleCreateListener)
	s.mux.HandleFunc("GET /api/listeners/{name}", s.handleGetListener)
	s.mux.HandleFunc("PATCH /api/listeners/{name}", s.handlePatchListener)
	s.mux.HandleFunc("DELETE /api/listeners/{name}", s.handleDeleteListener)
	s.mux.HandleFunc("POST /api/listeners/{name}/restart", s.handleRestartListener)
	s.mux.HandleFunc("GET /api/listeners/{name}/peers", s.handlePeerList)
	s.mux.HandleFunc("DELETE /api/listeners/{name}/peers", s.handlePeerDelete)
	s.mux.HandleFunc("POST /api/listeners/{name}/client-config", s.handleClientConfig)
	s.mux.HandleFunc("GET /api/metrics", s.handleMetrics)
	s.mux.HandleFunc("GET /api/audit", s.handleAudit)
	s.mux.HandleFunc("GET /api/logs", s.handleLogs)
	if s.profiles != "" {
		s.mux.HandleFunc("GET /api/profiles", s.handleListProfiles)
		s.mux.HandleFunc("POST /api/profiles", s.handleCreateProfile)
		s.mux.HandleFunc("GET /api/profiles/{name}", s.handleGetProfile)
		s.mux.HandleFunc("PATCH /api/profiles/{name}", s.handlePatchProfile)
		s.mux.HandleFunc("DELETE /api/profiles/{name}", s.handleDeleteProfile)
	}
	return s, nil
}

// Handler returns the mux so a caller can wrap it in TLS or run it through a
// unix-domain socket. Auth middleware is baked in: every /api/ request goes
// through requireToken.
//
// logRequest is on the outside, so a rejected request is logged too. With the
// order reversed -- which it was -- requireToken short-circuited before the
// logger ever ran, and failed authentication was the one thing the management
// plane never wrote a line about.
func (s *Server) Handler() http.Handler {
	return s.logRequest(s.requireToken(s.mux))
}

// Token returns the bearer token the panel uses to authenticate its /api
// fetches from the browser. It is exported so the caller (cmd/veepin wiring
// the UI handler) can inject it into the embedded dashboard template.
func (s *Server) Token() []byte { return s.token }

// CloseFleet stops every listener the Server's manager is running. It closes no
// HTTP anything -- the Server does not own a listening socket, its caller does.
//
// It was called Close, which is the trap the README named: a caller reaching for
// the conventional teardown on the HTTP-shaped object got a fleet-wide shutdown.
// The name now says so, and the mismatch is a compile error rather than an
// outage.
func (s *Server) CloseFleet() error { return s.mgr.Close() }

// --- Token boot ---

// bootToken reads or generates the bearer token at path. The "fresh" return is
// true on the path where the file did not exist and we minted a new one (the
// caller logs that once). The token is 256 random bits hex-encoded so it is
// safe to put on a command line and into a header line.
func bootToken(path string) ([]byte, bool, error) {
	if body, err := os.ReadFile(path); err == nil {
		trimmed := strings.TrimSpace(string(body))
		if trimmed == "" {
			// Atomic writes make this unreachable from a crash, but a file
			// zeroed by hand or by an older build can still get here. It is
			// unrecoverable as-is (an empty token is no token), so say what
			// will fix it rather than leaving the operator to guess why the
			// supervisor refuses to start.
			return nil, false, fmt.Errorf("token file %s is empty; delete it and the supervisor will mint a new one", path)
		}
		return []byte(trimmed), false, nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, false, err
	}
	// Generate 32 random bytes; hex-print to keep it printable and round-trip
	// safely through a shell. The owner-only permission matches the same
	// posture the listener config files carrying private keys use.
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, false, err
	}
	token := []byte(hex.EncodeToString(raw))
	// Written through a temp file and renamed, like every other config this
	// daemon owns. os.WriteFile truncates in place, so a crash between truncate
	// and write leaves an empty token file, and an empty token file is fatal on
	// every later boot -- it fails NewServer, which aborts the whole supervisor.
	if err := writeTokenAtomic(path, token); err != nil {
		return nil, false, err
	}
	return token, true, nil
}

// writeTokenAtomic writes the token to a temp file, syncs it, and renames it
// into place, so the token file is never observed half-written.
func writeTokenAtomic(path string, token []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, tokenName+".tmp.*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	// The temp file only needs to go away if we are not the ones renaming it;
	// a successful rename leaves the name vacant. Close-then-remove handles
	// every error path (a still-open file cannot be renamed on Windows, and
	// removing an open file would leak the fd on some platforms).
	keep := false
	defer func() {
		if !keep {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return err
	}
	body := append(append([]byte{}, token...), '\n')
	if _, err := tmp.Write(body); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	keep = true
	return os.Rename(tmpName, path)
}

// --- Middleware ---

// RequireHost rejects any request whose Host header names neither the loopback
// interface nor one of the extra hosts the operator deliberately bound to. It
// wraps the whole management listener -- panel and API together -- and the
// caller in cmd/veepin passes its -listen address as the extra.
//
// This is the DNS-rebinding guard, and it protects the panel more than the API.
// The panel is unauthenticated by necessity: it is the thing that hands the
// browser the token, so it cannot itself require one. The bearer header stops
// ordinary cross-origin abuse -- JavaScript on another site cannot set
// Authorization without a CORS preflight the supervisor never grants -- but a
// site that rebinds its own hostname to 127.0.0.1 stops being cross-origin at
// all. It can then fetch "/", read the token straight out of the page, and drive
// every endpoint with the operator's full authority.
//
// What gives it away is the Host header: the browser sends the name it dialled,
// so the rebound request arrives as `Host: attacker.example`, never as a
// loopback literal. Requiring one closes the hole. "localhost" is allowed
// alongside the IP literals because operators type it and it is not a name an
// attacker's DNS can claim.
func RequireHost(extra []string, next http.Handler) http.Handler {
	allow := make(map[string]bool, len(extra))
	for _, a := range extra {
		if h := hostOnly(a); h != "" {
			allow[h] = true
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hostAllowed(hostOnly(r.Host), allow) {
			next.ServeHTTP(w, r)
			return
		}
		http.Error(w, "forbidden: unrecognised Host header; the management plane "+
			"answers on loopback and on its own bind address only", http.StatusForbidden)
	})
}

// hostAllowed reports whether host may address the management plane.
func hostAllowed(host string, allow map[string]bool) bool {
	if host == "" {
		return false
	}
	if allow[host] {
		return true
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// hostOnly strips the port from a "host:port" authority, tolerating a bare host
// and unwrapping the brackets around an IPv6 literal.
func hostOnly(authority string) string {
	if h, _, err := net.SplitHostPort(authority); err == nil {
		return h
	}
	return strings.Trim(authority, "[]")
}

// requireToken is the auth layer. A request without a matching
// "Authorization: Bearer <token>" header gets a 401. Token comparison is
// constant-time. Trails /api/* only; the panel's static assets live at the root
// under the same handler in Phase 5 and are unauthenticated by design (the
// browser is a single tenant, localhost-only). For non-/api paths the function
// passes through.
func (s *Server) requireToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			next.ServeHTTP(w, r)
			return
		}
		got := bearer(r.Header.Get("Authorization"))
		if len(got) == 0 {
			http.Error(w, "unauthorized: missing bearer token", http.StatusUnauthorized)
			return
		}
		if subtle.ConstantTimeCompare(got, s.token) != 1 {
			http.Error(w, "unauthorized: bad token", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// logRequest emits one line per request: method, path, status. It is the
// minimum operator's view, and the only structured-ish output the management
// plane produces.
//
// A GET that succeeded is not logged, and that exclusion is load-bearing rather
// than cosmetic. The panel polls five endpoints every five seconds, so logging
// them wrote a line per second into the same logger that feeds the log ring --
// which meant the 1000-line ring held nothing but "GET /api/logs -> 200" after
// about seventeen minutes, and the build error an operator opened the panel to
// read was evicted by the act of reading it. The ring exists to answer "why is
// this listener in error state"; a feature that overwrites its own answer is
// worse than not having it.
//
// What is kept is everything that carries information: any failure (a 401 is
// the one security-relevant line here, and 4xx/5xx are what an operator greps
// for) and every mutation, whatever its outcome. Nothing that changed state, or
// tried to and was refused, goes unlogged.
func (s *Server) logRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		if r.Method == http.MethodGet && rec.status < 300 {
			return
		}
		s.log.Printf("mgmt: %s %s -> %d", r.Method, r.URL.Path, rec.status)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(s int) {
	r.status = s
	r.ResponseWriter.WriteHeader(s)
}

// bearer parses "Bearer <token>" headers. The lowercased comparison is per RFC
// 7235; an empty Authorization header returns nil.
func bearer(h string) []byte {
	const pfx = "bearer "
	if len(h) <= len(pfx) || !strings.EqualFold(h[:len(pfx)], pfx) {
		return nil
	}
	return []byte(strings.TrimSpace(h[len(pfx):]))
}

// --- Endpoints ---

// pathName pulls the {name} segment out of the route and checks it against the
// listener-name grammar before it is ever joined into a filesystem path. ServeMux
// makes an escape hard, but "hard" is not the bar for a string that becomes a
// filename, and the check is one line.
//
// Returns "" and writes the response when the name is not one the supervisor
// could ever have written; the caller returns on an empty result.
func (s *Server) pathName(w http.ResponseWriter, r *http.Request) string {
	name := r.PathValue("name")
	// A reserved name is a different answer from a missing one, and the
	// difference matters: "mgmt" and "profiles" are the config root's own
	// subdirectories, and the DELETE handler's orphan cleanup is an
	// os.RemoveAll of <dir>/<name>. Answering 404 for them would be true of the
	// listener and a lie about what just did not happen, so say it plainly.
	if confstore.ReservedName(name) {
		http.Error(w, "\""+name+"\" is reserved for the config root's own directory",
			http.StatusBadRequest)
		return ""
	}
	if !supervisor.ValidName(name) {
		http.Error(w, "no such listener", http.StatusNotFound)
		return ""
	}
	return name
}

// handleHealth answers a basic liveness probe.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	start := s.startedAt.Load()
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "uptime": time.Now().Unix() - start})
}

// handleAudit returns the recent mutation log, newest first. It is the answer
// to "what changed on this fleet since it started" — the panel renders it as
// recent activity, and an operator investigating a misconfiguration can see
// which listener was edited and whether the edit took.
func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	n, err := tailCount(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if n == 0 {
		n = auditCapacity
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": s.audit.recent(n)})
}

// handleLogs returns the supervisor's recent log lines, newest first. It is
// what lets the panel answer "why is this listener in error state" — the status
// field carries the last failure, but the log shows the sequence (build errors,
// hostnet messages, request lines) that produced it.
func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	if s.logs == nil {
		http.Error(w, "no log ring configured", http.StatusNotFound)
		return
	}
	n, err := tailCount(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"lines": s.logs.Recent(n)})
}

// ProtocolsResp is the body of GET /api/protocols.
type ProtocolsResp struct {
	// Protocols are the server protocols the supervisor can run listeners for.
	Protocols []ProtocolDesc `json:"protocols"`
	// ClientProtocols are the dial protocols the profile endpoints can store a
	// profile for, with their option schemas — the same form-rendering surface
	// as Protocols, for the client side.
	ClientProtocols []ProtocolDesc `json:"client_protocols,omitempty"`
}

// ProtocolDesc is one protocol's surface the panel can render.
//
// There was a `known bool` here, set to true on both of the two lines that
// construct one, while the `ok` from the OptsFor lookup that could have made it
// false was discarded. A JSON field with one possible value tells a consumer
// nothing, and this one read as though it might.
type ProtocolDesc struct {
	Name    string           `json:"name"`
	Options []client.OptSpec `json:"options,omitempty"`
}

func (s *Server) handleProtocols(w http.ResponseWriter, r *http.Request) {
	names := client.AllServerProtocols()
	out := ProtocolsResp{Protocols: make([]ProtocolDesc, 0, len(names))}
	for _, name := range names {
		opts, _ := client.ServerOptsFor(name)
		out.Protocols = append(out.Protocols, ProtocolDesc{Name: name, Options: opts})
	}
	clientNames := client.AllProtocols()
	out.ClientProtocols = make([]ProtocolDesc, 0, len(clientNames))
	for _, name := range clientNames {
		opts, _ := client.ClientOptsFor(name)
		out.ClientProtocols = append(out.ClientProtocols, ProtocolDesc{Name: name, Options: opts})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleListListeners(w http.ResponseWriter, r *http.Request) {
	statuses := s.mgr.All()
	// Add the on-disk configs for listeners that are not yet built (disabled).
	// The status' State="disabled" or "stopped" carries the info; full config
	// is fetched per-name via GET /api/listeners/{name}.
	writeJSON(w, http.StatusOK, map[string]any{"listeners": statuses})
}

// listenerResponse is one listener's full description: its visible status plus
// its on-disk config with secrets redacted. The panel combines the two views.
type listenerResponse struct {
	supervisor.Status
	Config supervisor.ListenerConfig `json:"config"`
}

func (s *Server) handleGetListener(w http.ResponseWriter, r *http.Request) {
	name := s.pathName(w, r)
	if name == "" {
		return
	}
	status := s.mgr.Status(name)
	if status.State == "unknown" {
		http.Error(w, "no such listener", http.StatusNotFound)
		return
	}
	cfg, err := supervisor.ParseListenerFile(supervisor.ListenerPath(s.dir, name))
	if err != nil {
		// Status said it exists; if the file is gone, treat as 404 instead of
		// surfacing a file-read error to the API caller.
		if errors.Is(err, fs.ErrNotExist) {
			http.Error(w, "no such listener", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	cfg.Options = redactOptions(cfg.Protocol, cfg.Options)
	writeJSON(w, http.StatusOK, listenerResponse{Status: status, Config: cfg})
}

func (s *Server) handleCreateListener(w http.ResponseWriter, r *http.Request) {
	// Read the body BEFORE taking the fleet lock. Taking it first meant an
	// authenticated client trickling one byte per minute held the lock that
	// serialises every create, patch, delete, restart and client-config in the
	// directory -- and with no ReadTimeout on the server there was no outer
	// bound on how long.
	//
	// Start from the same defaults a hand-written config file gets, so a create
	// that stays silent about "enabled" produces a running listener rather than
	// one that is stored, listed, and never started.
	cfg := supervisor.NewListenerConfig()
	if err := decodeJSON(r, &cfg); err != nil {
		s.audit.record("listener.create", "", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.mutate.Lock()
	defer s.mutate.Unlock()
	var res error
	name := cfg.Name
	defer func() { s.audit.record("listener.create", name, res) }()
	if err := cfg.Validate(); err != nil {
		res = err
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !supervisor.KnownProtocol(cfg.Protocol) {
		res = fmt.Errorf("mgmt: unknown protocol %q", cfg.Protocol)
		http.Error(w, "unknown protocol", http.StatusBadRequest)
		return
	}
	// The sentinel means "keep what is stored", and on a create there is nothing
	// stored to keep. mergeOptions honours it, but only PATCH goes through
	// mergeOptions -- a create decodes straight into the config, so a
	// GET-edit-POST-under-a-new-name round trip stored the literal string
	// "<redacted>" as the private key. Worse, being non-empty it then suppressed
	// key generation below, and the whole thing answered 201.
	if k := firstRedactedLiteral(cfg.Options); k != "" {
		res = fmt.Errorf("mgmt: %q is the redaction sentinel, not a value", k)
		http.Error(w, "option "+k+" is the literal \"<redacted>\": supply the real value, "+
			"or leave it empty to have one generated", http.StatusBadRequest)
		return
	}
	// POST creates. Without this check it also silently overwrote, so a repeated
	// create -- a double-submitted form, a re-run script -- replaced a live
	// listener's config, keys and all, and reported 201. Editing goes through
	// PATCH, which preserves what it is not told to change.
	if _, err := os.Stat(supervisor.ListenerPath(s.dir, cfg.Name)); err == nil {
		res = fmt.Errorf("mgmt: listener %q already exists", cfg.Name)
		http.Error(w, "a listener with that name already exists; PATCH it to edit",
			http.StatusConflict)
		return
	} else if !errors.Is(err, fs.ErrNotExist) {
		res = err
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Auto-generate any key material the protocol declares through OptSpec.Generate
	// before writing the config. Keys the operator supplied explicitly are left
	// untouched because generateListenerKeys skips any spec whose option already
	// has a value -- the dispatcher itself checks nothing.
	generated, err := generateListenerKeys(s.dir, &cfg)
	if err != nil {
		res = err
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := supervisor.WriteListenerFile(s.dir, cfg); err != nil {
		// The generated key material has no owner yet -- the config file that
		// would make the listener real was never written -- so take it out now.
		// Without this, a create that fails here leaves <dir>/<name>/ forever:
		// DELETE cleans it only on the success path, and no other code knows the
		// directory exists.
		_ = os.RemoveAll(filepath.Join(s.dir, cfg.Name))
		res = err
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := s.mgr.Apply(); err != nil {
		// The config file is on disk and the key material stays with it: 202,
		// the same "saved, but it did not come up" answer PATCH gives, and the
		// operator retries with POST .../restart once they have fixed whatever
		// it was. A failing build is usually something outside the config --
		// no CAP_NET_ADMIN, a port already bound -- not a reason to throw the
		// request away.
		//
		// This used to RemoveAll the key directory and keep the config file,
		// which is the worst of the three options: a stored config naming
		// ca.crt, tls.crt and tls.key at paths that no longer exist, and no
		// way to regenerate them, because generateListenerKeys skips a spec
		// whose option already has a value -- and every one of them did. Its
		// comment justified the deletion by saying the material an operator
		// must keep is recoverable from the config, which holds for a
		// WireGuard public key (it IS the config) and not at all for a TLS
		// chain, where the config holds only paths.
		res = err
		writeJSON(w, http.StatusAccepted,
			map[string]any{"status": "saved", "build_error": err.Error(),
				"generated": generated})
		return
	}
	// The generated map is surfaced once, on the create response: it carries the
	// values an operator must act on -- a WireGuard server's public key, which
	// has to be distributed to clients -- and which the config file stores but
	// the panel's declared-option form does not render.
	writeJSON(w, http.StatusCreated, map[string]any{
		"status":    s.mgr.Status(cfg.Name),
		"generated": generated,
	})
}

func (s *Server) handlePatchListener(w http.ResponseWriter, r *http.Request) {
	name := s.pathName(w, r)
	if name == "" {
		return
	}
	// Body first, then the lock: see handleCreateListener.
	var in listenerPatch
	if err := decodeJSON(r, &in); err != nil {
		s.audit.record("listener.patch", name, err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.mutate.Lock()
	defer s.mutate.Unlock()
	var res error
	defer func() { s.audit.record("listener.patch", name, res) }()
	existing, err := supervisor.ParseListenerFile(supervisor.ListenerPath(s.dir, name))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			res = err
			http.Error(w, "no such listener", http.StatusNotFound)
			return
		}
		res = err
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// A rename would have to move the file and retire the old listener. The
	// previous version did neither: it wrote <newname>.json, left <oldname>.json
	// in place, and rebuilt the old name -- so one edit produced two listeners.
	// Refuse it and say what to do instead.
	if in.Name != nil && *in.Name != name {
		res = errors.New("mgmt: rename refused")
		http.Error(w, "renaming a listener is not supported: create the new one and delete the old",
			http.StatusBadRequest)
		return
	}
	merged := in.applyTo(existing)
	if err := merged.Validate(); err != nil {
		res = err
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !supervisor.KnownProtocol(merged.Protocol) {
		res = fmt.Errorf("mgmt: unknown protocol %q", merged.Protocol)
		http.Error(w, "unknown protocol", http.StatusBadRequest)
		return
	}
	if err := supervisor.WriteListenerFile(s.dir, merged); err != nil {
		res = err
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Rebuild this listener, not Apply-all: an Apply that fails because
	// another unrelated listener fails should not block this PATCH's effect.
	if err := s.mgr.Rebuild(name); err != nil {
		// The new config file is on disk; the rebuild error is reported but
		// the operator can retry via POST .../restart. HTTP 202 conveys
		// "accepted, partially applied".
		res = err
		writeJSON(w, http.StatusAccepted,
			map[string]any{"status": "saved", "build_error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, s.mgr.Status(name))
}

func (s *Server) handleDeleteListener(w http.ResponseWriter, r *http.Request) {
	name := s.pathName(w, r)
	if name == "" {
		return
	}
	s.mutate.Lock()
	defer s.mutate.Unlock()
	var res error
	defer func() { s.audit.record("listener.delete", name, res) }()
	// Stop reports "no listener named X" if the running set does not have it;
	// we proceed with the file removal so Delete is idempotent for a listener
	// that crashed but whose file is still present. Deliberately discarded, not
	// recorded: routing it into res made every delete of a stopped or disabled
	// listener show up in the audit log as a red failure next to its own 200.
	_ = s.mgr.Stop(name)
	// Clean up any generated key material stored alongside the listener. This
	// runs before the file-missing early-return below: a create that failed
	// between key generation and the config write leaves the key directory
	// behind with no config file to DELETE, and the orphan can only be reached
	// by a delete that does not insist on the file existing first.
	keyErr := os.RemoveAll(filepath.Join(s.dir, name))
	if err := supervisor.DeleteListenerFile(s.dir, name); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			if keyErr != nil {
				res = fmt.Errorf("mgmt: removing key material: %w", keyErr)
				http.Error(w, res.Error(), http.StatusInternalServerError)
				return
			}
			res = err
			http.Error(w, "no such listener", http.StatusNotFound)
			return
		}
		res = err
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if keyErr != nil {
		res = fmt.Errorf("mgmt: removing key material: %w", keyErr)
		http.Error(w, res.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"deleted": name})
}

func (s *Server) handleRestartListener(w http.ResponseWriter, r *http.Request) {
	name := s.pathName(w, r)
	if name == "" {
		return
	}
	s.mutate.Lock()
	defer s.mutate.Unlock()
	var res error
	defer func() { s.audit.record("listener.restart", name, res) }()
	if err := s.mgr.Rebuild(name); err != nil {
		res = err
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, s.mgr.Status(name))
}

// handlePeerList returns the peer list for a running listener whose protocol
// implements client.PeerDescriber. Protocols that do not implement it return
// an empty array; the panel renders nothing rather than showing a misleading
// "no peers" which could be read as "no clients".
func (s *Server) handlePeerList(w http.ResponseWriter, r *http.Request) {
	name := s.pathName(w, r)
	if name == "" {
		return
	}
	// Peer listing goes through the manager, which resolves the live server
	// under its locks and holds them across the PeerDescriber call. Reading the
	// raw server handle here and calling Peers() on it would race a concurrent
	// rebuild or stop that Close()s the server mid-call -- a panel poll racing
	// a rekey is exactly when peer lists are wanted, and a use-after-close on
	// the management plane is not a diagnostic anyone asked for.
	peers, avail := s.mgr.Peers(name)
	switch avail {
	case supervisor.PeersNoSuchListener:
		http.Error(w, "no such listener", http.StatusNotFound)
		return
	case supervisor.PeersNotRunning:
		// 200, not 404. The listener exists; it just has no live server to ask.
		// Answering 404 told an operator inspecting a listener in error state
		// that the listener did not exist, while the status half of the same
		// panel view answered 200 for it.
		writeJSON(w, http.StatusOK, map[string]any{
			"peers":       []client.PeerInfo{},
			"unavailable": "the listener is not running",
		})
		return
	case supervisor.PeersUnsupported:
		writeJSON(w, http.StatusOK, map[string]any{
			"peers":       []client.PeerInfo{},
			"unavailable": "this protocol does not report peers",
		})
		return
	}
	if peers == nil {
		peers = []client.PeerInfo{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"peers": peers})
}

// handlePeerDelete removes a configured peer from a WireGuard-family listener
// (wireguard and amneziawg, which share the same peers options). Stranded
// peers are the point: a client-config response lost after a successful
// provision leaves a peer on the listener that nobody holds the private key
// for, and before this endpoint there was no way to take it back out except
// hand-editing the config file.
//
// The public key travels in the query string, not the path: it is base64, so a
// path segment would be split by any "/" or "+" in the key.
func (s *Server) handlePeerDelete(w http.ResponseWriter, r *http.Request) {
	name := s.pathName(w, r)
	if name == "" {
		return
	}
	s.mutate.Lock()
	defer s.mutate.Unlock()
	var res error
	defer func() { s.audit.record("listener.peer-delete", name, res) }()
	pub := r.URL.Query().Get("key")
	if pub == "" {
		res = errors.New("mgmt: peer key is required")
		http.Error(w, "peer key is required (?key=<public-key>)", http.StatusBadRequest)
		return
	}
	cfg, err := supervisor.ParseListenerFile(supervisor.ListenerPath(s.dir, name))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			res = err
			http.Error(w, "no such listener", http.StatusNotFound)
			return
		}
		res = err
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if cfg.Protocol != "wireguard" && cfg.Protocol != "amneziawg" {
		res = fmt.Errorf("mgmt: %s has no configurable peers", cfg.Protocol)
		http.Error(w, "peer management is a WireGuard-family feature", http.StatusBadRequest)
		return
	}
	peers, err := parseWGPeers(cfg.Options[wireguard.OptServerPeers])
	if err != nil {
		res = err
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// The single-peer options are a peer too; removing that one clears them
	// rather than leaving an orphaned allowed-ips.
	wasSingle := cfg.Options[wireguard.OptServerPeerPublicKey] == pub
	kept := make([]wireguard.ServerPeer, 0, len(peers))
	found := wasSingle
	for _, p := range peers {
		if p.PublicKey == pub {
			found = true
			continue
		}
		kept = append(kept, p)
	}
	if !found {
		res = fmt.Errorf("mgmt: no peer with that key on %s", name)
		http.Error(w, "no such peer", http.StatusNotFound)
		return
	}
	// Persist the reduced peer set, then rebuild; on a failed rebuild the peer
	// goes back in, exactly as client-config generation rolls a failed
	// provision back out.
	//
	// The whole options map is snapshotted rather than the peers key alone. A
	// single-peer removal clears peer-public-key and peer-allowed-ips too, and
	// restoring only the peers JSON put none of that back: a failed rebuild
	// dropped the peer permanently. That is the one unrecoverable case here --
	// unlike a generated client config, the server never held the client's
	// private key, so a lost peer public key cannot be re-issued. Snapshotting
	// the map keeps the rollback correct for whatever key a later protocol adds.
	prevOptions := maps.Clone(cfg.Options)
	if len(kept) == 0 {
		delete(cfg.Options, wireguard.OptServerPeers)
	} else {
		body, err := json.Marshal(kept)
		if err != nil {
			res = err
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		cfg.Options[wireguard.OptServerPeers] = string(body)
	}
	if wasSingle {
		delete(cfg.Options, wireguard.OptServerPeerPublicKey)
		delete(cfg.Options, wireguard.OptServerPeerAllowedIPs)
	}
	if err := supervisor.WriteListenerFile(s.dir, cfg); err != nil {
		res = err
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := s.mgr.Rebuild(name); err != nil {
		cfg.Options = prevOptions
		if rerr := supervisor.WriteListenerFile(s.dir, cfg); rerr != nil {
			s.log.Warnf("mgmt: %s: rolling back a failed peer removal: %v", name, rerr)
		}
		res = err
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": pub, "listener": name})
}

// generateListenerKeys inspects the protocol's OptSpec declarations for entries
// with a non-empty Generate field. For each such entry whose value is currently
// empty in cfg.Options, it calls keygen.Generate to create key material on disk
// and updates cfg.Options with the resulting file paths or inline values.
//
// Multi-file generators (e.g. "tls" returns both "cert" and "key") set every key
// they produce, so the handler does not need to deduce which keys were affected.
//
// Whether a generator runs is decided per GENERATOR, not per spec, in a first
// pass over the declarations. Deciding it per spec meant partial operator input
// went undetected: the loop skipped a spec whose value was already supplied
// before recording that its generator had been considered, so
//
//	POST {"protocol":"openvpn","options":{"key":"/etc/my/server.key"}}
//
// left "ca" empty, ran x509-chain anyway, O_TRUNC-wrote all three PEMs, and
// then merged only into the empty keys -- storing a generated certificate
// alongside the operator's unrelated private key. The listener answered 201 and
// failed every handshake. A generator is all-or-nothing, so a partial supply is
// refused rather than half-honoured.
//
// The returned map is the generated material the protocol does NOT declare as an
// option (a WireGuard public key, which the parse never reads but the operator
// must distribute): the handler merges it into cfg.Options so it persists with
// the config, and surfaces it separately for the create response.
func generateListenerKeys(configDir string, cfg *supervisor.ListenerConfig) (map[string]string, error) {
	decl, ok := client.ServerOptsFor(cfg.Protocol)
	if !ok {
		return nil, nil
	}
	declared := make(map[string]bool, len(decl))
	for _, spec := range decl {
		declared[spec.Key] = true
	}
	// First pass: for each generator, which of its keys the operator supplied.
	supplied := map[string][]string{}
	missing := map[string][]string{}
	for _, spec := range decl {
		if spec.Generate == "" {
			continue
		}
		if cfg.Options[spec.Key] != "" {
			supplied[spec.Generate] = append(supplied[spec.Generate], spec.Key)
		} else {
			missing[spec.Generate] = append(missing[spec.Generate], spec.Key)
		}
	}
	generated := map[string]string{}
	seen := map[string]bool{}
	for _, spec := range decl {
		if spec.Generate == "" {
			continue
		}
		if cfg.Options == nil {
			cfg.Options = map[string]string{}
		}
		if seen[spec.Generate] {
			continue
		}
		seen[spec.Generate] = true
		// Nothing missing: the operator brought their own, in full.
		if len(missing[spec.Generate]) == 0 {
			continue
		}
		// Something missing and something supplied: refuse rather than write
		// over half of a set that has to agree with itself.
		if got := supplied[spec.Generate]; len(got) > 0 {
			slices.Sort(got)
			want := slices.Clone(missing[spec.Generate])
			slices.Sort(want)
			return nil, fmt.Errorf(
				"mgmt: %q generates %s together: supply all of them or none (missing %s)",
				spec.Generate, strings.Join(got, ", "), strings.Join(want, ", "))
		}

		// A pq- listener needs an ML-DSA credential, not an ECDSA one: its own
		// contract refuses a classical certificate at construction, so
		// generating one would produce a listener that cannot start. The
		// OptSpec tables are shared with the base protocol (a variant declares
		// none of its own), so the generator is selected here from the
		// listener's protocol rather than from the spec.
		genType := keygen.PostQuantumType(spec.Generate, client.IsVariant(cfg.Protocol))

		kv, err := keygen.Generate(cfg.Name, configDir, genType, spec.Key, cfg.Hostnames)
		if err != nil {
			return nil, fmt.Errorf("mgmt: keygen %q for %q: %w", genType, cfg.Name, err)
		}
		for k, v := range kv {
			if cfg.Options[k] == "" {
				cfg.Options[k] = v
			}
			if !declared[k] {
				generated[k] = v
			}
		}
	}
	if len(generated) == 0 {
		return nil, nil
	}
	return generated, nil
}

// --- Helpers ---

// listenerPatch is a presence-aware view of a PATCH body.
//
// A plain supervisor.ListenerConfig cannot serve as one: encoding/json leaves an
// absent field at its zero value, so `"enabled": false` and an omitted "enabled"
// decode identically. The merge then has no way to tell "leave it alone" from
// "turn it off", and the previous version resolved that with
//
//	merged.Enabled = in.Enabled || existing.Enabled
//
// which made every boolean one-way: unchecking "enabled" or "-setup-nat" in the
// panel silently did nothing, and there was no way to disable a listener through
// the API at all. Pointers distinguish the two cases, which is the whole reason
// they are here.
type listenerPatch struct {
	Name      *string            `json:"name,omitempty"`
	Protocol  *string            `json:"protocol,omitempty"`
	Options   *map[string]string `json:"options,omitempty"`
	SetupNAT  *bool              `json:"setup_nat,omitempty"`
	WAN       *string            `json:"wan,omitempty"`
	Enabled   *bool              `json:"enabled,omitempty"`
	Hostnames *[]string          `json:"hostnames,omitempty"`
}

// applyTo merges the fields the request actually carried onto existing, leaving
// every field it did not mention alone.
func (p listenerPatch) applyTo(existing supervisor.ListenerConfig) supervisor.ListenerConfig {
	out := existing
	if p.Name != nil {
		out.Name = *p.Name
	}
	if p.Protocol != nil {
		out.Protocol = *p.Protocol
	}
	if p.Options != nil {
		out.Options = mergeOptions(existing.Options, *p.Options)
	}
	if p.SetupNAT != nil {
		out.SetupNAT = *p.SetupNAT
	}
	if p.WAN != nil {
		out.WAN = *p.WAN
	}
	if p.Enabled != nil {
		out.Enabled = *p.Enabled
	}
	if p.Hostnames != nil {
		out.Hostnames = *p.Hostnames
	}
	// A protocol change re-bases which keys are secret, because redaction is
	// resolved against the CURRENT protocol's specs. Carrying the old
	// protocol's options across meant a single PATCH could declassify them:
	//
	//	POST  {"protocol":"ikev2","options":{"psk":"REAL"}}
	//	PATCH {"protocol":"toy"}          -- toy declares no psk spec
	//	GET   -> {"options":{"psk":"REAL"}}   in the clear
	//
	// Dropping what the new protocol does not declare is both the safe answer
	// and the correct one: a key the new parse never reads is dead config
	// either way, and keeping it only preserved it somewhere it could leak.
	if p.Protocol != nil && *p.Protocol != existing.Protocol {
		out.Options = keepDeclaredOptions(out.Protocol, out.Options)
	}
	return out
}

// keepDeclaredOptions drops every key the protocol does not declare a server
// OptSpec for. A protocol with no declaration is left alone: the API cannot
// tell which of its keys are meaningful, and every registered protocol declares
// one, so this is a fallback rather than a live path.
func keepDeclaredOptions(protocol string, opts map[string]string) map[string]string {
	specs, ok := client.ServerOptsFor(protocol)
	if !ok || opts == nil {
		return opts
	}
	declared := make(map[string]bool, len(specs))
	for _, sp := range specs {
		declared[sp.Key] = true
	}
	out := make(map[string]string, len(opts))
	for k, v := range opts {
		if declared[k] {
			out[k] = v
		}
	}
	return out
}

// mergeOptions combines existing with the patch. A key the patch does not
// mention is left alone, which is what makes a hand-written curl PATCH carrying
// one option safe. Two values are special:
//
//	"<redacted>"  keep the stored value. The API never reveals a real secret, so
//	              a GET-then-PATCH round trip must not clobber the key with the
//	              placeholder it was shown.
//	""            delete the key. This is how the panel clears a field, since it
//	              submits every option the protocol declares on every save and
//	              needs a way to say "unset". Overloading empty is safe because
//	              the server parse functions already read a missing key and an
//	              empty one identically.
func mergeOptions(existing, patch map[string]string) map[string]string {
	out := make(map[string]string, len(existing)+len(patch))
	maps.Copy(out, existing)
	for k, v := range patch {
		switch v {
		case redacted:
		case "":
			delete(out, k)
		default:
			out[k] = v
		}
	}
	return out
}

// tailCount reads the ?n= tail bound shared by /api/logs and /api/audit. Zero
// means "everything the ring holds", which is bounded by construction.
//
// A malformed value is a 400 rather than a silent fallback to everything. It
// used to be the latter -- ?n=abc, ?n=-5 and ?n=0 all quietly meant the whole
// ring, so a typo in a curl returned a thousand lines with nothing to say the
// parameter had been ignored.
func tailCount(r *http.Request) (int, error) {
	q := r.URL.Query().Get("n")
	if q == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(q)
	if err != nil {
		return 0, fmt.Errorf("mgmt: n=%q is not a number", q)
	}
	if n < 0 {
		return 0, fmt.Errorf("mgmt: n=%d is negative", n)
	}
	return n, nil
}

// firstRedactedLiteral returns the first key whose value is the redaction
// sentinel, or "" if none is. Sorted, so the message a form full of them
// produces is the same one every time.
func firstRedactedLiteral(opts map[string]string) string {
	keys := make([]string, 0, len(opts))
	for k, v := range opts {
		if v == redacted {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return ""
	}
	slices.Sort(keys)
	return keys[0]
}

// redactOptions returns a copy of opts with the values of the secret keys a
// protocol declares replaced by the "<redacted>" sentinel.
//
// A copy, not an edit in place: the caller's map is the one that was just parsed
// off disk, and a function whose job is "hide the secrets" quietly overwriting
// its input with placeholders is one refactor away from writing those
// placeholders back to the file.
//
// Protocols without a ServerOpts declaration are returned unchanged -- the API
// cannot tell which of their keys are secret. Every registered protocol declares
// one, and cmd/veepin's TestServerOptSpecsMatchTheKeysTheProtocolReads keeps the
// declarations honest, so this branch is a fallback rather than a live path.
func redactOptions(protocol string, opts map[string]string) map[string]string {
	specs, _ := client.ServerOptsFor(protocol)
	return client.Redact(specs, opts)
}

// decodeJSON reads a request body sized for the small config documents the API
// accepts, into a target pointer. A nil body or a body over 1 MiB is rejected.
//
// Every error here is prefixed, because these four are not internal: they are
// the 400 body an operator reads, and they are what s.audit.record stores, so
// /api/audit showed a bare "empty body" with nothing naming the subsystem it
// came from.
func decodeJSON(r *http.Request, v any) error {
	const maxBody = 1 << 20 // 1 MiB; a listener config is much smaller
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if err != nil {
		return fmt.Errorf("mgmt: reading body: %w", err)
	}
	if len(body) == 0 {
		return errors.New("mgmt: empty body")
	}
	if len(body) > maxBody {
		return errors.New("mgmt: body exceeds 1 MiB")
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("mgmt: decoding JSON: %w", err)
	}
	return nil
}

// writeJSON serializes v with pretty indentation so a curl response is readable
// without help. Pretty output costs bytes, never correctness. HTML escaping is
// disabled so the "<redacted>" sentinel survives a Serialize/Deserialize/Patch
// round trip verbatim: the JSON default would escape "<" to "\u003c", which is
// safe but visually obscures the sentinel an operator reads in a curl.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}
