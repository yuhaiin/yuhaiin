package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/pprof"
	runtimepprof "runtime/pprof"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/google/pprof/profile"
)

const (
	profilerMaxSessions = 10
	profilerMaxBytes    = 128 << 20
	profilerMaxCapture  = 32 << 20
	profilerTTL         = 30 * time.Minute
)

type profilerSessionInfo struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"`
	Seconds     int       `json:"seconds"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"createdAt"`
	CompletedAt time.Time `json:"completedAt"`
	Size        int       `json:"size"`
	Error       string    `json:"error,omitempty"`
}

type profilerSession struct {
	info   profilerSessionInfo
	raw    []byte
	cancel context.CancelFunc
	view   profilerView
}

type profilerService struct {
	mu         sync.Mutex
	sessions   map[string]*profilerSession
	cpuRunning atomic.Bool
	done       chan struct{}
	closed     bool
	stopOnce   sync.Once

	viewerInitErr error
}

var activeProfiler atomic.Pointer[profilerService]

func newProfilerService() *profilerService {
	p := &profilerService{sessions: make(map[string]*profilerSession), done: make(chan struct{})}
	go p.reapLoop()
	return p
}

func (p *profilerService) reapLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			p.mu.Lock()
			p.evictLocked(time.Now())
			p.mu.Unlock()
		case <-p.done:
			return
		}
	}
}

func (p *profilerService) stop() {
	p.stopOnce.Do(func() {
		p.mu.Lock()
		p.closed = true
		for _, s := range p.sessions {
			if s.cancel != nil {
				s.cancel()
			}
		}
		clear(p.sessions)
		p.mu.Unlock()
		close(p.done)
	})
}

func (p *profilerService) clear() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, s := range p.sessions {
		if s.cancel != nil {
			s.cancel()
		}
	}
	clear(p.sessions)
}

func (p *profilerService) evictLocked(now time.Time) {
	for id, s := range p.sessions {
		if s.info.Status != "running" && now.Sub(s.info.CompletedAt) > profilerTTL {
			delete(p.sessions, id)
		}
	}
	var finished []*profilerSession
	total := 0
	for _, s := range p.sessions {
		if s.info.Status != "running" {
			finished = append(finished, s)
			total += len(s.raw)
		}
	}
	sort.Slice(finished, func(i, j int) bool {
		return finished[i].info.CreatedAt.Before(finished[j].info.CreatedAt)
	})
	for i, s := range finished {
		if len(finished)-i <= profilerMaxSessions && total <= profilerMaxBytes {
			break
		}
		delete(p.sessions, s.info.ID)
		total -= len(s.raw)
	}
}

func (p *profilerService) list() []profilerSessionInfo {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.evictLocked(time.Now())
	out := make([]profilerSessionInfo, 0, len(p.sessions))
	for _, s := range p.sessions {
		out = append(out, s.info)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	return out
}

func (p *profilerService) get(id string) (*profilerSession, profilerSessionInfo, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.evictLocked(time.Now())
	s, ok := p.sessions[id]
	if !ok {
		return nil, profilerSessionInfo{}, false
	}
	return s, s.info, true
}

func (p *profilerService) remove(id string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	s, ok := p.sessions[id]
	if !ok {
		return false
	}
	delete(p.sessions, id)
	if s.cancel != nil {
		s.cancel()
	}
	return true
}

func (p *profilerService) start(kind string, seconds int) (profilerSessionInfo, int, error) {
	switch kind {
	case "cpu", "heap", "allocs", "goroutine", "mutex", "block":
	default:
		return profilerSessionInfo{}, http.StatusBadRequest, errors.New("unsupported profile type")
	}
	if seconds < 0 || seconds > 120 ||
		(kind == "cpu" && seconds == 0) {
		return profilerSessionInfo{}, http.StatusBadRequest, errors.New("invalid sampling duration")
	}
	if !pprofEnabled.Load() {
		return profilerSessionInfo{}, http.StatusForbidden, errors.New("profiling is disabled")
	}
	if kind == "cpu" && !p.cpuRunning.CompareAndSwap(false, true) {
		return profilerSessionInfo{}, http.StatusConflict, errors.New("a CPU profile is already running")
	}
	releaseCPU := func() {
		if kind == "cpu" {
			p.cpuRunning.Store(false)
		}
	}
	var secret [24]byte
	if _, err := rand.Read(secret[:]); err != nil {
		releaseCPU()
		return profilerSessionInfo{}, http.StatusInternalServerError, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	info := profilerSessionInfo{
		ID: hex.EncodeToString(secret[:]), Type: kind, Seconds: seconds,
		Status: "running", CreatedAt: time.Now(),
	}
	p.mu.Lock()
	if p.closed || !pprofEnabled.Load() {
		p.mu.Unlock()
		cancel()
		releaseCPU()
		return profilerSessionInfo{}, http.StatusForbidden, errors.New("profiling is disabled")
	}
	active := 0
	for _, s := range p.sessions {
		if s.info.Status == "running" {
			active++
		}
	}
	if active >= 3 {
		p.mu.Unlock()
		cancel()
		releaseCPU()
		return profilerSessionInfo{}, http.StatusTooManyRequests, errors.New("too many active profiles")
	}
	p.sessions[info.ID] = &profilerSession{info: info, cancel: cancel}
	p.mu.Unlock()
	go func() {
		defer cancel()
		defer releaseCPU()
		raw, err := collectProfile(ctx, kind, seconds)
		p.mu.Lock()
		defer p.mu.Unlock()
		s, ok := p.sessions[info.ID]
		if !ok {
			return
		}
		s.info.CompletedAt = time.Now()
		s.cancel = nil
		switch {
		case ctx.Err() != nil || !pprofEnabled.Load():
			s.info.Status = "cancelled"
		case err != nil:
			s.info.Status = "failed"
			s.info.Error = err.Error()
		default:
			s.info.Status = "completed"
			s.info.Size = len(raw)
			s.raw = raw
		}
		p.evictLocked(time.Now())
	}()
	return info, http.StatusAccepted, nil
}

func collectProfile(ctx context.Context, kind string, seconds int) ([]byte, error) {
	var buf bytes.Buffer
	if kind == "cpu" {
		// Coordinate with the existing runtime pprof toggle. Only the active
		// collector owns the CPU sampling window.
		pprofMu.Lock()
		if !pprofEnabled.Load() {
			pprofMu.Unlock()
			return nil, errors.New("profiling is disabled")
		}
		err := runtimepprof.StartCPUProfile(&buf)
		pprofMu.Unlock()
		if err != nil {
			return nil, err
		}
		timer := time.NewTimer(time.Duration(seconds) * time.Second)
		select {
		case <-timer.C:
		case <-ctx.Done():
		}
		timer.Stop()
		pprofMu.Lock()
		runtimepprof.StopCPUProfile()
		pprofMu.Unlock()
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	} else {
		collector := &profileResponse{header: make(http.Header)}
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/debug/pprof/"+kind, nil)
		if seconds > 0 {
			req.URL.RawQuery = "seconds=" + strconv.Itoa(seconds)
		}
		pprof.Handler(kind).ServeHTTP(collector, req)
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if collector.err != nil {
			return nil, collector.err
		}
		if collector.status != 0 && collector.status != http.StatusOK {
			return nil, fmt.Errorf("pprof returned HTTP %d: %s", collector.status, collector.buffer.String())
		}
		buf = collector.buffer
	}
	if buf.Len() == 0 || buf.Len() > profilerMaxCapture {
		return nil, fmt.Errorf("invalid profile size: %d bytes", buf.Len())
	}
	if _, err := profile.ParseData(buf.Bytes()); err != nil {
		return nil, fmt.Errorf("invalid pprof data: %w", err)
	}
	return buf.Bytes(), nil
}

type profileResponse struct {
	header http.Header
	buffer bytes.Buffer
	status int
	err    error
}

func (w *profileResponse) Header() http.Header    { return w.header }
func (w *profileResponse) WriteHeader(status int) { w.status = status }
func (w *profileResponse) Write(b []byte) (int, error) {
	if w.buffer.Len()+len(b) > profilerMaxCapture {
		w.err = errors.New("profile exceeds 32 MiB")
		return 0, w.err
	}
	return w.buffer.Write(b)
}

func registerProfilerHTTP(app *AppInstance) {
	p := newProfilerService()
	p.viewerInitErr = prepareProfilerViewerConfigDir(app.ConfigPath)
	if p.viewerInitErr != nil {
		log.Warn("pprof web viewer config unavailable", "err", p.viewerInitErr)
	}
	app.profiler = p
	activeProfiler.Store(p)

	HandleFunc(app.Mux, nil, "GET /api/v2/profiler/sessions", func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		return json.NewEncoder(w).Encode(struct {
			Enabled  bool                  `json:"enabled"`
			Sessions []profilerSessionInfo `json:"sessions"`
		}{pprofEnabled.Load(), p.list()})
	})
	HandleFunc(app.Mux, nil, "POST /api/v2/profiler/sessions", func(w http.ResponseWriter, r *http.Request) error {
		var input struct {
			Type    string `json:"type"`
			Seconds int    `json:"seconds"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&input); err != nil {
			http.Error(w, "invalid profile request", http.StatusBadRequest)
			return nil
		}
		info, status, err := p.start(input.Type, input.Seconds)
		if err != nil {
			http.Error(w, err.Error(), status)
			return nil
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(status)
		return json.NewEncoder(w).Encode(info)
	})
	HandleFunc(app.Mux, nil, "DELETE /api/v2/profiler/sessions/{id}", func(w http.ResponseWriter, r *http.Request) error {
		if !p.remove(r.PathValue("id")) {
			http.NotFound(w, r)
			return nil
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	})
	// The unpredictable, expiring session ID is a scoped viewer capability.
	// Unlike the API, it never embeds the administrator's Basic credentials.
	app.Mux.HandleFunc("GET /debug/profiler/", p.serveView)
}

func (p *profilerService) serveView(w http.ResponseWriter, r *http.Request) {
	if !pprofEnabled.Load() {
		http.NotFound(w, r)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/debug/profiler/")
	id, suffix, _ := strings.Cut(path, "/")
	if len(id) != 48 {
		http.NotFound(w, r)
		return
	}
	s, info, ok := p.get(id)
	if !ok || info.Status != "completed" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if suffix == "" {
		http.Redirect(w, r, "/debug/profiler/"+id+"/flamegraph", http.StatusFound)
		return
	}
	if suffix == "download" {
		w.Header().Set("Content-Type", "application/vnd.google.protobuf+gzip")
		w.Header().Set("Content-Disposition", "attachment; filename=profile.pb.gz")
		_, _ = w.Write(s.raw)
		return
	}
	if suffix == "graph" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'")
		_, _ = io.WriteString(w, graphBridgePage)
		return
	}
	if suffix == "dot" {
		// The session ID is an expiring unguessable capability. The React app
		// may run on another origin; requests omit browser credentials.
		w.Header().Set("Access-Control-Allow-Origin", "*")
		if !validProfilerGraphQuery(r.URL.RawQuery) {
			http.Error(w, "invalid graph query", http.StatusBadRequest)
			return
		}
		dot, err := profilerDOT(s.raw, r.URL.Query())
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/vnd.graphviz; charset=utf-8")
		_, _ = io.WriteString(w, dot)
		return
	}

	if p.viewerInitErr != nil {
		http.Error(w, "pprof viewer unavailable: "+p.viewerInitErr.Error(), http.StatusInternalServerError)
		return
	}
	handlers, err := s.view.handlersFor(s.raw)
	if err != nil {
		http.Error(w, "pprof viewer unavailable: "+err.Error(), http.StatusInternalServerError)
		return
	}
	h := handlers["/"+suffix]
	if h == nil || suffix == "saveconfig" || suffix == "deleteconfig" {
		http.NotFound(w, r)
		return
	}
	// Official templates use relative paths, allowing them to live beneath
	// /debug/profiler/<session-id>/ without an additional listener.
	clone := r.Clone(r.Context())
	clone.URL.Path = "/" + suffix
	// google/pprof uses a process-global currentConfig; DOT generation
	// temporarily changes it. Keep official handlers outside that window.
	profilerViewerInitMu.Lock()
	defer profilerViewerInitMu.Unlock()
	h.ServeHTTP(profilerResponsiveWriter{ResponseWriter: w}, clone)
}
