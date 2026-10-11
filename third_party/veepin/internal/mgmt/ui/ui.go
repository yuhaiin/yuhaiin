// Package ui is the supervisor's server-rendered web panel. It is plain
// html/template and inlined vanilla JavaScript over an embed.FS; no npm, no
// bundle step, no third-party dependency. The browser talks to the same
// /api/* endpoints the CLI does, authenticating each fetch with the bearer
// token this package embeds into the dashboard as a JS global.
//
// The panel is served at the root of the management HTTP server; /api/* is
// reserved for the data plane. The panel itself is reachable without a token
// because the management server binds to localhost by default -- the bearer
// token is then the per-request boundary, sent from the browser on each fetch
// against /api/*. Operators who bind to a routable interface are expected to
// stand up mTLS or SSH-tunnel in front of the panel: that posture is the
// subject of doc/security.md.
package ui

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"net/http"
	"strings"

	"github.com/xen0bit/veepin/internal/vlog"
)

//go:embed templates/*
var templatesFS embed.FS

// Handler is the http.Handler that serves the panel pages.
type Handler struct {
	token string
	tmpl  *template.Template
	log   *vlog.Logger
}

// NewHandler parses the embedded templates once and stores the bearer token
// for injection into the dashboard; the browser uses it for its /api fetches.
// Returns an error if the embedded templates fail to parse, which a build
// embeds once and which should therefore never happen.
//
// logger is the supervisor's logger -- the same one feeding mgmt.LogRing, so a
// render failure shows up in the panel's own /api/logs tail. It was an
// fmt.Printf to stdout, which meant the panel's one failure mode was the one
// thing the panel could not show you. A nil logger discards.
func NewHandler(token string, logger *vlog.Logger) (*Handler, error) {
	tmpl, err := template.ParseFS(templatesFS, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("ui: parsing embedded templates: %w", err)
	}
	if logger == nil {
		logger = vlog.Discard()
	}
	return &Handler{token: token, tmpl: tmpl, log: logger}, nil
}

// pageData is the dashboard render context. The Token field is the only
// secret; everything else is decorative.
type pageData struct {
	Token     string
	InitialJS string
}

// ServeHTTP routes the dashboard, the add/edit form pages (for listeners and
// profiles), and the shared panel.js asset. /api/* is owned by api.go; this
// handler only sees requests that did not match the api. Form paths:
//
//	/listeners/new, /listeners/{name}    listener add / edit
//	/profiles/new, /profiles/{name}      profile add / edit
//
// Anything else falls through to a plain 404 so the management API's own 404
// for /api/missing is unaffected.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch p := r.URL.Path; {
	case p == "/" || p == "":
		h.render(w, "dashboard.html")
	case p == "/assets/panel.js":
		h.serveAsset(w, r, "templates/panel.js", "text/javascript; charset=utf-8")
	case p == "/listeners/new":
		h.render(w, "form.html", pageData{Token: h.token, InitialJS: "new"})
	case p == "/profiles/new":
		h.render(w, "form.html", pageData{Token: h.token, InitialJS: "new-profile"})
	case strings.HasPrefix(p, "/listeners/"):
		name := p[len("/listeners/"):]
		if name == "" || strings.Contains(name, "/") {
			http.NotFound(w, r)
			return
		}
		h.render(w, "form.html", pageData{Token: h.token, InitialJS: "edit:" + name})
	case strings.HasPrefix(p, "/profiles/"):
		name := p[len("/profiles/"):]
		if name == "" || strings.Contains(name, "/") {
			http.NotFound(w, r)
			return
		}
		h.render(w, "form.html", pageData{Token: h.token, InitialJS: "edit-profile:" + name})
	default:
		http.NotFound(w, r)
	}
}

// serveAsset writes one file from the embedded tree with the given content type.
// nosniff because the declared type is the correct one and a browser that
// second-guesses it on a page holding the bearer token is not a trade worth
// making.
func (h *Handler) serveAsset(w http.ResponseWriter, r *http.Request, name, ctype string) {
	body, err := templatesFS.ReadFile(name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(body)
}

// render executes a template into the response.
//
// It renders into a buffer first, so a failure can still become a 500 with a
// body. Executing straight into the ResponseWriter meant a template that failed
// halfway had already sent 200 and a truncated page, and the code that noticed
// could do nothing about it -- the comment there promised "write a 500 in the
// body" above a line that wrote nothing to the body at all.
func (h *Handler) render(w http.ResponseWriter, name string, data ...pageData) {
	var ctx pageData
	if len(data) > 0 {
		ctx = data[0]
	}
	ctx.Token = h.token

	var buf bytes.Buffer
	if err := h.tmpl.ExecuteTemplate(&buf, name, ctx); err != nil {
		h.log.Warnf("ui: template %s failed: %v", name, err)
		http.Error(w, "panel template failed to render; see the supervisor log",
			http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(buf.Bytes())
}
