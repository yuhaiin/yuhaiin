package yuhaiin

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/Asutorufa/yuhaiin/internal/version"
	"github.com/Asutorufa/yuhaiin/pkg/log"
)

// PlatformActions is implemented by the Android background service for the
// platform API operations that need Android or must stop the core itself.
type PlatformActions interface {
	// RestoreConfig restores the validated backup at path. It runs
	// asynchronously: the core stops, the backup is imported, and the core
	// starts again. The file is owned by the implementation afterwards.
	RestoreConfig(path string) error
	// RestartCore restarts the core asynchronously, for settings read at start.
	RestartCore() error
	// PrivacyState returns the localized policy and consent receipts as JSON.
	PrivacyState() string
	// WithdrawConsent stops the VPN and withdraws VPN and app-list consent.
	WithdrawConsent() error
	// UpdateState returns the software update state as JSON.
	UpdateState() string
	// UpdateAction runs "check", "apply", "permission" or "channel" (arg).
	UpdateAction(action, arg string) error
	// AppInfo returns application version information as JSON.
	AppInfo() string
}

var (
	platformActionsMu sync.Mutex
	platformActions   PlatformActions
)

func SetPlatformActions(a PlatformActions) {
	platformActionsMu.Lock()
	platformActions = a
	platformActionsMu.Unlock()
}

func currentPlatformActions() PlatformActions {
	platformActionsMu.Lock()
	defer platformActionsMu.Unlock()
	return platformActions
}

const (
	maxBackupBytes  = 32 << 20
	routeContentKey = "route_content_"
)

var presetRoutes = []string{AdvRouteAll, AdvRouteNonLocal}

func (p *platformAPI) registerFeatures() {
	p.mux.HandleFunc("GET "+platformAPIPrefix+"app", p.authorized(p.appInfo))
	p.mux.HandleFunc("POST "+platformAPIPrefix+"core/restart", p.authorized(p.restartCore))

	p.mux.HandleFunc("GET "+platformAPIPrefix+"routes", p.authorized(p.listRoutes))
	p.mux.HandleFunc("POST "+platformAPIPrefix+"routes", p.authorized(p.createRoute))
	p.mux.HandleFunc("PUT "+platformAPIPrefix+"routes", p.authorized(p.saveRoute))
	p.mux.HandleFunc("POST "+platformAPIPrefix+"routes/delete", p.authorized(p.deleteRoute))

	p.mux.HandleFunc("GET "+platformAPIPrefix+"logs", p.authorized(p.logs))
	p.mux.HandleFunc("POST "+platformAPIPrefix+"logs/export", p.authorized(p.exportLogs))

	p.mux.HandleFunc("POST "+platformAPIPrefix+"backup/export", p.authorized(p.exportBackup))
	p.mux.HandleFunc("POST "+platformAPIPrefix+"backup/preview", p.authorizedLarge(p.previewBackup))
	p.mux.HandleFunc("POST "+platformAPIPrefix+"backup/restore", p.authorizedLarge(p.restoreBackup))

	p.mux.HandleFunc("GET "+platformAPIPrefix+"privacy", p.authorized(p.privacy))
	p.mux.HandleFunc("POST "+platformAPIPrefix+"privacy/withdraw", p.authorized(p.withdraw))

	p.mux.HandleFunc("GET "+platformAPIPrefix+"update", p.authorized(p.updateState))
	p.mux.HandleFunc("POST "+platformAPIPrefix+"update", p.authorized(p.updateAction))

	// One-time download links for WebView downloads, which Android's
	// DownloadManager fetches without the session cookie.
	p.mux.HandleFunc("GET "+platformAPIPrefix+"download/{token}", p.download)
}

func (p *platformAPI) authorizedLarge(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if status, msg := p.authorize(r); status != 0 {
			writeError(w, status, "unauthorized", msg)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxBackupBytes+1)
		next(w, r)
	}
}

func requireActions(w http.ResponseWriter) PlatformActions {
	a := currentPlatformActions()
	if a == nil {
		writeError(w, http.StatusServiceUnavailable, "provider_unavailable", "Android platform service is not available")
	}
	return a
}

func writeRawJSON(w http.ResponseWriter, data string) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, data)
}

// ---- app ----

func (p *platformAPI) appInfo(w http.ResponseWriter, _ *http.Request) {
	info := map[string]any{"core": map[string]string{"version": version.Version, "commit": version.GitCommit}}
	if a := currentPlatformActions(); a != nil {
		var app map[string]any
		if json.Unmarshal([]byte(a.AppInfo()), &app) == nil {
			info["app"] = app
		}
	}
	writeJSON(w, http.StatusOK, info)
}

func (p *platformAPI) restartCore(w http.ResponseWriter, _ *http.Request) {
	a := requireActions(w)
	if a == nil {
		return
	}
	if err := a.RestartCore(); err != nil {
		writeError(w, http.StatusInternalServerError, "restart_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]bool{"restarting": true})
}

// ---- route profiles ----

type routeProfile struct {
	Name    string `json:"name"`
	Preset  bool   `json:"preset"`
	Active  bool   `json:"active"`
	Content string `json:"content"`
}

var routesMu sync.Mutex

func routeNames() []string {
	names := readStringSet(savedRoutesKey)
	if len(names) == 0 {
		names = slices.Clone(presetRoutes)
	}
	return names
}

func activeRoute() string {
	if v := GetStore().GetString(AdvRouteKey); v != "" {
		return v
	}
	return AdvRouteAll
}

func (p *platformAPI) listRoutes(w http.ResponseWriter, _ *http.Request) {
	routesMu.Lock()
	defer routesMu.Unlock()
	active := activeRoute()
	var out []routeProfile
	for _, name := range routeNames() {
		out = append(out, routeProfile{Name: name, Preset: slices.Contains(presetRoutes, name), Active: name == active,
			Content: GetStore().GetString(routeContentKey + name)})
	}
	writeJSON(w, http.StatusOK, map[string]any{"active": active, "profiles": out})
}

func validRouteName(name string) bool {
	if name == "" || len([]rune(name)) > 80 {
		return false
	}
	for _, r := range name {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' && r != '-' {
			return false
		}
	}
	return true
}

// validRouteContent accepts one CIDR or address per line, as the VPN builder does.
func validRouteContent(content string) error {
	if len(content) > 1<<20 {
		return errors.New("route list is too large")
	}
	for i, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if _, err := netip.ParsePrefix(line); err == nil {
			continue
		}
		if _, err := netip.ParseAddr(line); err == nil {
			continue
		}
		return fmt.Errorf("line %d: %q is not a CIDR or IP address", i+1, line)
	}
	return nil
}

func writeRouteNames(names []string) {
	data, _ := json.Marshal(names)
	GetStore().PutString(savedRoutesKey, string(data))
}

func (p *platformAPI) createRoute(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if err := json.UnmarshalRead(r.Body, &req); err != nil || !validRouteName(req.Name) {
		writeError(w, http.StatusBadRequest, "invalid_request", "use 1-80 letters, digits, '_' or '-'")
		return
	}
	routesMu.Lock()
	defer routesMu.Unlock()
	names := routeNames()
	if slices.Contains(names, req.Name) {
		writeError(w, http.StatusConflict, "exists", "a route profile with this name exists")
		return
	}
	GetStore().PutString(routeContentKey+req.Name, "")
	writeRouteNames(append(names, req.Name))
	writeJSON(w, http.StatusOK, routeProfile{Name: req.Name})
}

func (p *platformAPI) saveRoute(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name    string `json:"name"`
		Content string `json:"content"`
	}
	if err := json.UnmarshalRead(r.Body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := validRouteContent(req.Content); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	routesMu.Lock()
	defer routesMu.Unlock()
	if !slices.Contains(routeNames(), req.Name) {
		writeError(w, http.StatusNotFound, "not_found", "unknown route profile")
		return
	}
	previous := GetStore().GetString(routeContentKey + req.Name)
	GetStore().PutString(routeContentKey+req.Name, req.Content)
	if req.Name == activeRoute() && previous != req.Content {
		RequestVpnReconfigure()
	}
	writeJSON(w, http.StatusOK, routeProfile{Name: req.Name, Preset: slices.Contains(presetRoutes, req.Name), Content: req.Content})
}

func (p *platformAPI) deleteRoute(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if err := json.UnmarshalRead(r.Body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if slices.Contains(presetRoutes, req.Name) {
		writeError(w, http.StatusBadRequest, "invalid_request", "built-in route profiles cannot be deleted")
		return
	}
	routesMu.Lock()
	defer routesMu.Unlock()
	names := routeNames()
	if !slices.Contains(names, req.Name) {
		writeError(w, http.StatusNotFound, "not_found", "unknown route profile")
		return
	}
	if activeRoute() == req.Name {
		// Always keep a valid selection.
		GetStore().PutString(AdvRouteKey, AdvRouteAll)
		RequestVpnReconfigure()
	}
	writeRouteNames(slices.DeleteFunc(names, func(n string) bool { return n == req.Name }))
	GetStore().PutString(routeContentKey+req.Name, "")
	writeJSON(w, http.StatusOK, map[string]bool{"deleted": true})
}

// ---- logs ----

// readLogcat reads this app's log buffer; Android limits apps to their own UID.
var readLogcat = func(ctx context.Context, lines int) ([]byte, error) {
	// App processes may run without PATH; logcat is a system binary.
	bin := "/system/bin/logcat"
	if _, err := os.Stat(bin); err != nil {
		bin = "logcat"
	}
	return exec.CommandContext(ctx, bin, "-d", "-v", "threadtime", "-t", strconv.Itoa(lines)).Output()
}

func logLines(r *http.Request) int {
	n, _ := strconv.Atoi(r.URL.Query().Get("lines"))
	if n <= 0 {
		n = 1000
	}
	return min(n, 20000)
}

func (p *platformAPI) logs(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	data, err := readLogcat(ctx, logLines(r))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "logs_failed", err.Error())
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write(data)
}

func (p *platformAPI) exportLogs(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	data, err := readLogcat(ctx, 20000)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "logs_failed", err.Error())
		return
	}
	name := "yuhaiin-" + time.Now().Format("20060102-150405") + ".log"
	writeJSON(w, http.StatusOK, map[string]string{"url": downloads.add(name, "text/plain; charset=utf-8", data), "name": name})
}

// ---- backup ----

func (p *platformAPI) exportBackup(w http.ResponseWriter, _ *http.Request) {
	data, err := ExportConfig()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "backup_failed", err.Error())
		return
	}
	name := "yuhaiin-backup-" + time.Now().Format("20060102-150405") + ".json"
	writeJSON(w, http.StatusOK, map[string]string{"url": downloads.add(name, "application/json", data), "name": name})
}

type backupPreview struct {
	CreatedAt   string `json:"createdAt"`
	Nodes       int    `json:"nodes"`
	Routes      int    `json:"routes"`
	Preferences int    `json:"preferences"`
}

func previewOf(data []byte) (backupPreview, error) {
	var root struct {
		Format    string `json:"format"`
		Version   int    `json:"version"`
		CreatedAt string `json:"createdAt"`
		Tables    map[string]struct {
			Rows []jsontext.Value `json:"rows"`
		} `json:"tables"`
	}
	if err := json.Unmarshal(data, &root); err != nil {
		return backupPreview{}, fmt.Errorf("invalid backup: %w", err)
	}
	// Version 2 is what the core writes when gateway guard rows exist; v1 apps
	// write the same format, so their backups restore too.
	if root.Format != "yuhaiin-config" || (root.Version != 1 && root.Version != 2) {
		return backupPreview{}, errors.New("unsupported backup format")
	}
	return backupPreview{CreatedAt: root.CreatedAt, Nodes: len(root.Tables["nodes_v2"].Rows),
		Routes: len(root.Tables["route_rules_v2"].Rows), Preferences: len(root.Tables["android_extra_preferences"].Rows)}, nil
}

func readBackup(w http.ResponseWriter, r *http.Request) ([]byte, backupPreview, bool) {
	data, err := io.ReadAll(r.Body)
	if err != nil || len(data) == 0 || len(data) > maxBackupBytes {
		writeError(w, http.StatusRequestEntityTooLarge, "invalid_request", "backups must be between 1 byte and 32 MiB")
		return nil, backupPreview{}, false
	}
	preview, err := previewOf(data)
	if err == nil {
		err = ValidateConfig(data)
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_backup", err.Error())
		return nil, backupPreview{}, false
	}
	return data, preview, true
}

func (p *platformAPI) previewBackup(w http.ResponseWriter, r *http.Request) {
	if _, preview, ok := readBackup(w, r); ok {
		writeJSON(w, http.StatusOK, preview)
	}
}

func (p *platformAPI) restoreBackup(w http.ResponseWriter, r *http.Request) {
	a := requireActions(w)
	if a == nil {
		return
	}
	data, _, ok := readBackup(w, r)
	if !ok {
		return
	}
	dir := filepath.Join(savepath, "restore")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		writeError(w, http.StatusInternalServerError, "restore_failed", err.Error())
		return
	}
	file, err := os.CreateTemp(dir, "restore-*.json")
	if err == nil {
		_, err = io.Copy(file, bytes.NewReader(data))
		err = errors.Join(err, file.Close())
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "restore_failed", err.Error())
		return
	}
	if err := a.RestoreConfig(file.Name()); err != nil {
		_ = os.Remove(file.Name())
		writeError(w, http.StatusInternalServerError, "restore_failed", err.Error())
		return
	}
	// The core stops and starts again; the WebView reconnects to the new session.
	writeJSON(w, http.StatusAccepted, map[string]bool{"restoring": true})
}

// ---- privacy and update (Android owned) ----

func (p *platformAPI) privacy(w http.ResponseWriter, _ *http.Request) {
	if a := requireActions(w); a != nil {
		writeRawJSON(w, a.PrivacyState())
	}
}

func (p *platformAPI) withdraw(w http.ResponseWriter, _ *http.Request) {
	a := requireActions(w)
	if a == nil {
		return
	}
	if err := a.WithdrawConsent(); err != nil {
		writeError(w, http.StatusInternalServerError, "withdraw_failed", err.Error())
		return
	}
	writeRawJSON(w, a.PrivacyState())
}

func (p *platformAPI) updateState(w http.ResponseWriter, _ *http.Request) {
	if a := requireActions(w); a != nil {
		writeRawJSON(w, a.UpdateState())
	}
}

func (p *platformAPI) updateAction(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Action  string `json:"action"`
		Channel string `json:"channel"`
	}
	if err := json.UnmarshalRead(r.Body, &req); err != nil || !slices.Contains([]string{"check", "apply", "permission", "channel"}, req.Action) {
		writeError(w, http.StatusBadRequest, "invalid_request", `action must be check, apply, permission or channel`)
		return
	}
	if req.Action == "channel" && !slices.Contains([]string{"stable", "beta", "main"}, req.Channel) {
		writeError(w, http.StatusBadRequest, "invalid_request", "unknown channel")
		return
	}
	a := requireActions(w)
	if a == nil {
		return
	}
	if err := a.UpdateAction(req.Action, req.Channel); err != nil {
		writeError(w, http.StatusConflict, "update_failed", err.Error())
		return
	}
	writeRawJSON(w, a.UpdateState())
}

// ---- one-time downloads ----

type downloadItem struct {
	name, contentType string
	data              []byte
	expires           time.Time
	uses              int
}

// The WebView requests a download URL once before handing it to Android's
// DownloadManager, which requests it again; allow a few fetches.
const downloadMaxUses = 3

type downloadStore struct {
	mu    sync.Mutex
	items map[string]downloadItem
}

var downloads = &downloadStore{items: map[string]downloadItem{}}

const downloadTTL = 2 * time.Minute

func (d *downloadStore) add(name, contentType string, data []byte) string {
	var b [24]byte
	_, _ = rand.Read(b[:])
	token := base64.RawURLEncoding.EncodeToString(b[:])
	d.mu.Lock()
	defer d.mu.Unlock()
	now := time.Now()
	for k, v := range d.items {
		if now.After(v.expires) {
			delete(d.items, k)
		}
	}
	d.items[token] = downloadItem{name: name, contentType: contentType, data: data, expires: now.Add(downloadTTL)}
	return platformAPIPrefix + "download/" + token
}

func (d *downloadStore) take(token string) (downloadItem, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	item, ok := d.items[token]
	if !ok || time.Now().After(item.expires) {
		delete(d.items, token)
		return downloadItem{}, false
	}
	item.uses++
	if item.uses >= downloadMaxUses {
		delete(d.items, token)
	} else {
		d.items[token] = item
	}
	return item, true
}

// download serves a link created by an authorized request. The unguessable
// token is short-lived and limited to a few fetches, and only loopback peers
// are served.
func (p *platformAPI) download(w http.ResponseWriter, r *http.Request) {
	if !isLoopbackPeer(r.RemoteAddr) {
		writeError(w, http.StatusForbidden, "unauthorized", "downloads are only available on this device")
		return
	}
	item, ok := downloads.take(r.PathValue("token"))
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "download link expired")
		return
	}
	w.Header().Set("Content-Type", item.contentType)
	w.Header().Set("Content-Disposition", `attachment; filename="`+item.name+`"`)
	w.Header().Set("Content-Length", strconv.Itoa(len(item.data)))
	if _, err := w.Write(item.data); err != nil {
		log.Debug("platform download write failed", "err", err)
	}
}
