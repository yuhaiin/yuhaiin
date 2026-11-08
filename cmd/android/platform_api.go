package yuhaiin

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/platformvpn"
)

// The Android platform API exposes the few device functions the Web UI needs
// (VPN on/off, VPN status, per-app VPN and Android preferences). It is mounted
// under platformAPIPrefix on the management server, outside the generic RPC
// API, and is never served cross-origin.
//
// Authorization does not rely on Origin or Host. Every request except the
// capability probe must:
//
//  1. come from a loopback peer (LAN clients are rejected even when LAN
//     management is enabled),
//  2. carry the per-start platform token in the HttpOnly, SameSite=Strict
//     cookie that only the in-app WebView receives from the background
//     service over Binder, and
//  3. for state changes, carry platformRequestHeader with a JSON body, which
//     a cross-site page cannot send without a CORS preflight this API never
//     approves.
const (
	platformAPIPrefix     = "/android/v1/"
	PlatformCookieName    = "yuhaiin_android_platform"
	platformRequestHeader = "X-Yuhaiin-Platform-Request"
)

// AppCatalog is implemented by Android and lists installed applications for
// per-app VPN. It returns a JSON array of {"name","packageName","system"}, or
// an error starting with "consent_required" without the app-list consent.
type AppCatalog interface {
	InstalledApps() (string, error)
}

var (
	appCatalogMu sync.Mutex
	appCatalog   AppCatalog
)

func SetAppCatalog(c AppCatalog) {
	appCatalogMu.Lock()
	appCatalog = c
	appCatalogMu.Unlock()
}

func currentAppCatalog() AppCatalog {
	appCatalogMu.Lock()
	defer appCatalogMu.Unlock()
	return appCatalog
}

func newPlatformToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

type platformAPI struct {
	app   *App
	token string
	mux   *http.ServeMux
}

func newPlatformAPI(app *App, token string) *platformAPI {
	p := &platformAPI{app: app, token: token, mux: http.NewServeMux()}
	p.mux.HandleFunc("GET "+platformAPIPrefix+"capabilities", p.capabilities)
	p.mux.HandleFunc("GET "+platformAPIPrefix+"status", p.authorized(p.status))
	p.mux.HandleFunc("POST "+platformAPIPrefix+"vpn", p.authorized(p.setVPN))
	p.mux.HandleFunc("POST "+platformAPIPrefix+"vpn/reconfigure", p.authorized(p.reconfigure))
	p.mux.HandleFunc("GET "+platformAPIPrefix+"settings", p.authorized(p.getSettings))
	p.mux.HandleFunc("PUT "+platformAPIPrefix+"settings", p.authorized(p.putSettings))
	p.mux.HandleFunc("GET "+platformAPIPrefix+"apps", p.authorized(p.apps))
	p.registerFeatures()
	return p
}

func (p *platformAPI) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == strings.TrimSuffix(platformAPIPrefix, "/") || strings.HasPrefix(r.URL.Path, platformAPIPrefix) {
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			p.mux.ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

type apiError struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.MarshalWrite(w, v); err != nil {
		log.Debug("write platform API response failed", "err", err)
	}
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	var e apiError
	e.Error.Code, e.Error.Message = code, message
	writeJSON(w, status, e)
}

func isLoopbackPeer(remote string) bool {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.Unmap().IsLoopback()
}

// authorize implements the checks described at the top of this file.
func (p *platformAPI) authorize(r *http.Request) (int, string) {
	if !isLoopbackPeer(r.RemoteAddr) {
		return http.StatusForbidden, "android platform API is only available on this device"
	}
	cookie, err := r.Cookie(PlatformCookieName)
	if err != nil || p.token == "" || subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(p.token)) != 1 {
		return http.StatusUnauthorized, "missing or invalid platform session"
	}
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
		return http.StatusForbidden, "cross-site platform requests are not allowed"
	}
	if r.Method != http.MethodGet {
		if r.Header.Get(platformRequestHeader) != "1" {
			return http.StatusForbidden, "missing " + platformRequestHeader + " header"
		}
		if mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mediaType != "application/json" {
			return http.StatusUnsupportedMediaType, "platform requests must use application/json"
		}
	}
	return 0, ""
}

func (p *platformAPI) authorized(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if status, msg := p.authorize(r); status != 0 {
			writeError(w, status, "unauthorized", msg)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		next(w, r)
	}
}

type platformCapabilities struct {
	Platform string   `json:"platform"`
	Version  int      `json:"version"`
	Features []string `json:"features"`
	// Session tells the UI whether this client holds the platform session.
	// Only the in-app WebView does; browsers on the LAN see false and should
	// hide device controls.
	Session bool `json:"session"`
}

// capabilities is unauthenticated so the Web UI can detect the platform
// without inspecting the User-Agent. It reveals no state.
func (p *platformAPI) capabilities(w http.ResponseWriter, r *http.Request) {
	status, _ := p.authorize(r)
	writeJSON(w, http.StatusOK, platformCapabilities{
		Platform: "android",
		Version:  1,
		Features: []string{"vpn", "vpn.reconfigure", "perApp", "settings", "nativeActions"},
		Session:  status == 0,
	})
}

type coreStatus struct {
	Running   bool  `json:"running"`
	StartedAt int64 `json:"startedAt"`
	Port      int32 `json:"port"`
	HTTPS     bool  `json:"https"`
	LANAccess bool  `json:"lanAccess"`
}

type vpnStatusResponse struct {
	Enabled       bool               `json:"enabled"`
	InboundID     string             `json:"inboundId"`
	InboundStatus string             `json:"inboundStatus,omitempty"`
	InboundError  string             `json:"inboundError,omitempty"`
	Runtime       platformvpn.Status `json:"runtime"`
	Authorization *vpnAuthorization  `json:"authorization,omitempty"`
}

type statusResponse struct {
	Platform string            `json:"platform"`
	Core     coreStatus        `json:"core"`
	VPN      vpnStatusResponse `json:"vpn"`
}

func (p *platformAPI) statusSnapshot(r *http.Request) statusResponse {
	running := p.app.Running()
	var startedAt int64
	if running {
		startedAt = p.app.startedAt.UnixMilli()
	}
	resp := statusResponse{Platform: "android", Core: coreStatus{
		Running:   running,
		StartedAt: startedAt,
		Port:      p.app.port,
		HTTPS:     p.app.https,
		LANAccess: GetStore().GetBoolean(AllowLanKey),
	}}
	resp.VPN.Runtime = platformvpn.Default.Status()
	if auth, ok := currentAuthorization(); ok {
		resp.VPN.Authorization = &auth
	}
	if cfg, err := p.app.androidTun(); err == nil {
		resp.VPN.Enabled, resp.VPN.InboundID = cfg.Enabled, cfg.ID
		if contracts := p.app.contractStore(); contracts != nil {
			if statuses, err := contracts.Statuses(r.Context()); err == nil {
				for _, s := range statuses {
					if s.ID == cfg.ID {
						resp.VPN.InboundStatus, resp.VPN.InboundError = s.Status, s.LastError
					}
				}
			}
		}
	}
	return resp
}

func (p *platformAPI) status(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, p.statusSnapshot(r))
}

func (p *platformAPI) setVPN(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled *bool `json:"enabled"`
	}
	if err := json.UnmarshalRead(r.Body, &req); err != nil || req.Enabled == nil {
		writeError(w, http.StatusBadRequest, "invalid_request", `expected {"enabled": true|false}`)
		return
	}
	if *req.Enabled {
		// Never persist "enabled" without the OS authorization. The UI must
		// send the user to the in-app consent and VpnService.prepare dialog.
		auth, ok := currentAuthorization()
		switch {
		case !ok:
			writeError(w, http.StatusServiceUnavailable, platformvpn.CodeProviderUnavailable, "Android VPN service is not available")
			return
		case !auth.Consent:
			writeError(w, http.StatusConflict, platformvpn.CodeConsentRequired, "the VPN data disclosure must be accepted in the app")
			return
		case !auth.Prepared:
			writeError(w, http.StatusConflict, platformvpn.CodePermissionRequired, "Android VPN permission must be granted in the app")
			return
		}
	}
	if err := p.app.SetVpnEnabled(*req.Enabled); err != nil {
		code := platformvpn.ErrorCode(err)
		status := http.StatusInternalServerError
		if code == platformvpn.CodePermissionRequired || code == platformvpn.CodeConsentRequired || code == platformvpn.CodeBusy {
			status = http.StatusConflict
		}
		writeError(w, status, code, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, p.statusSnapshot(r))
}

func (p *platformAPI) reconfigure(w http.ResponseWriter, r *http.Request) {
	RequestVpnReconfigure()
	writeJSON(w, http.StatusAccepted, p.statusSnapshot(r))
}

func (p *platformAPI) apps(w http.ResponseWriter, _ *http.Request) {
	catalog := currentAppCatalog()
	if catalog == nil {
		writeError(w, http.StatusServiceUnavailable, platformvpn.CodeProviderUnavailable, "app catalog is not available")
		return
	}
	data, err := catalog.InstalledApps()
	if err != nil {
		if strings.Contains(err.Error(), platformvpn.CodeConsentRequired) {
			writeError(w, http.StatusConflict, platformvpn.CodeConsentRequired, "the installed-apps disclosure must be accepted in the app")
			return
		}
		writeError(w, http.StatusInternalServerError, "apps_failed", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"apps":` + data + `}`))
}

// Android preferences exposed to the Web UI. VPN marks values the VpnService
// Builder reads; changing one rebuilds the running VPN.
type settingKind int

const (
	settingBool settingKind = iota
	settingEnum
	settingStringSet
	settingRoute
	settingPort
)

type androidSetting struct {
	field  string
	key    string
	kind   settingKind
	values []string
	def    string
	vpn    bool
	// restart marks values the core reads only when it starts.
	restart bool
	// apply updates runtime state immediately after a change.
	apply func(string)
}

const CoreBackgroundPolicyKey = "core_background_policy"

var androidSettings = []androidSetting{
	{field: "perApp", key: AdvPerAppKey, kind: settingBool, def: "false", vpn: true},
	{field: "appBypass", key: AdvAppBypassKey, kind: settingBool, def: "false", vpn: true},
	{field: "appList", key: AdvAppListKey, kind: settingStringSet, vpn: true},
	{field: "routeProfile", key: AdvRouteKey, kind: settingRoute, def: AdvRouteAll, vpn: true},
	{field: "mtuProfile", key: AdvVPNMTUProfileKey, kind: settingEnum, values: VPNMTUProfilesValue, def: VPNMTUAutoValue, vpn: true},
	{field: "meteredMode", key: "vpn_metered_mode", kind: settingEnum, values: []string{"auto", "metered"}, def: "auto", vpn: true},
	{field: "appendHTTPProxy", key: AppendHttpProxyToVpnKey, kind: settingBool, def: "false", vpn: true},
	{field: "autoConnect", key: AdvAutoConnectKey, kind: settingBool, def: "false"},
	{field: "bootConnectPolicy", key: "boot_connect_policy", kind: settingEnum, values: []string{"always", "charging_only", "skip_in_power_save"}, def: "always"},
	{field: "notificationSpeed", key: "android_notification_speed", kind: settingBool, def: "false"},
	{field: "coreBackgroundPolicy", key: CoreBackgroundPolicyKey, kind: settingEnum, values: []string{"while_needed", "always"}, def: "while_needed"},
	{field: "trackUnderlyingNetwork", key: AdvRegisterUnderlyingNetworkCallbackKey, kind: settingBool, def: "true"},
	{field: "allowLan", key: AllowLanKey, kind: settingBool, def: "false", restart: true},
	{field: "processLookupMode", key: AdvProcessLookupModeKey, kind: settingEnum, values: ProcessLookupModesValue, def: ProcessLookupAlwaysValue,
		apply: func(v string) { configuration.ProcessLookupMode.Store(v) }},
	{field: "httpProxyPort", key: NewHTTPPortKey, kind: settingPort, def: "0", vpn: true},
}

const savedRoutesKey = "saved_routes_list"

func readStringSet(key string) []string {
	var values []string
	if raw := GetStore().GetString(key); raw != "" {
		_ = json.Unmarshal([]byte(raw), &values)
	}
	slices.Sort(values)
	return slices.Compact(values)
}

func (s androidSetting) read() any {
	store := GetStore()
	switch s.kind {
	case settingBool:
		raw := store.GetString(s.key)
		if raw == "" {
			raw = s.def
		}
		return raw == "true"
	case settingStringSet:
		v := readStringSet(s.key)
		if v == nil {
			v = []string{}
		}
		return v
	case settingPort:
		return int(store.GetInt(s.key))
	default:
		raw := store.GetString(s.key)
		if raw == "" {
			raw = s.def
		}
		return raw
	}
}

type settingsResponse struct {
	Restart       []string            `json:"restartRequired"`
	Values        map[string]any      `json:"values"`
	RouteProfiles []string            `json:"routeProfiles"`
	Options       map[string][]string `json:"options"`
}

func (p *platformAPI) settingsSnapshot() settingsResponse {
	resp := settingsResponse{Values: map[string]any{}, Options: map[string][]string{}}
	for _, s := range androidSettings {
		resp.Values[s.field] = s.read()
		if s.kind == settingEnum {
			resp.Options[s.field] = s.values
		}
		if s.restart {
			resp.Restart = append(resp.Restart, s.field)
		}
	}
	resp.RouteProfiles = readStringSet(savedRoutesKey)
	if len(resp.RouteProfiles) == 0 {
		resp.RouteProfiles = slices.Clone(AdvRoutes)
	}
	return resp
}

func (p *platformAPI) getSettings(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, p.settingsSnapshot())
}

var settingsWriteMu sync.Mutex

func (p *platformAPI) putSettings(w http.ResponseWriter, r *http.Request) {
	var req map[string]jsontext.Value
	if err := json.UnmarshalRead(r.Body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	settingsWriteMu.Lock()
	defer settingsWriteMu.Unlock()
	routes := p.settingsSnapshot().RouteProfiles
	type write func()
	var writes []write
	vpnChanged := false
	for field, raw := range req {
		i := slices.IndexFunc(androidSettings, func(s androidSetting) bool { return s.field == field })
		if i < 0 {
			writeError(w, http.StatusBadRequest, "invalid_request", "unknown setting "+field)
			return
		}
		s := androidSettings[i]
		var next any
		switch s.kind {
		case settingBool:
			var v bool
			if err := json.Unmarshal(raw, &v); err != nil {
				writeError(w, http.StatusBadRequest, "invalid_request", field+" must be a boolean")
				return
			}
			next = v
			writes = append(writes, func() { GetStore().PutBoolean(s.key, v) })
		case settingPort:
			var v int
			if err := json.Unmarshal(raw, &v); err != nil || v < 0 || v > 65535 {
				writeError(w, http.StatusBadRequest, "invalid_request", field+" must be a port between 0 and 65535")
				return
			}
			next = v
			writes = append(writes, func() { GetStore().PutInt(s.key, int32(v)) })
		case settingStringSet:
			var v []string
			if err := json.Unmarshal(raw, &v); err != nil || len(v) > 4096 {
				writeError(w, http.StatusBadRequest, "invalid_request", field+" must be a list of package names")
				return
			}
			for _, name := range v {
				if !validPackageName(name) {
					writeError(w, http.StatusBadRequest, "invalid_request", "invalid package name "+name)
					return
				}
			}
			slices.Sort(v)
			v = slices.Compact(v)
			if v == nil {
				v = []string{}
			}
			next = v
			data, _ := json.Marshal(v)
			writes = append(writes, func() { GetStore().PutString(s.key, string(data)) })
		default:
			var v string
			if err := json.Unmarshal(raw, &v); err != nil {
				writeError(w, http.StatusBadRequest, "invalid_request", field+" must be a string")
				return
			}
			allowed := s.values
			if s.kind == settingRoute {
				allowed = routes
			}
			if !slices.Contains(allowed, v) {
				writeError(w, http.StatusBadRequest, "invalid_request", "unsupported "+field+" "+v)
				return
			}
			next = v
			writes = append(writes, func() {
				GetStore().PutString(s.key, v)
				if s.apply != nil {
					s.apply(v)
				}
			})
		}
		if s.vpn && !equalSetting(s.read(), next) {
			vpnChanged = true
		}
	}
	for _, apply := range writes {
		apply()
	}
	if vpnChanged {
		RequestVpnReconfigure()
	}
	writeJSON(w, http.StatusOK, p.settingsSnapshot())
}

func equalSetting(a, b any) bool {
	as, aok := a.([]string)
	bs, bok := b.([]string)
	if aok && bok {
		return slices.Equal(as, bs)
	}
	return a == b
}

// validPackageName accepts Android application IDs (segments of letters,
// digits and underscores separated by dots).
func validPackageName(name string) bool {
	if len(name) == 0 || len(name) > 255 || !strings.Contains(name, ".") {
		return false
	}
	for seg := range strings.SplitSeq(name, ".") {
		if seg == "" {
			return false
		}
		for i, c := range seg {
			letter := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
			digit := i > 0 && c >= '0' && c <= '9'
			if !letter && !digit && c != '_' {
				return false
			}
		}
	}
	return true
}
