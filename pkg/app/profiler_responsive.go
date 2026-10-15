package app

import (
	"bytes"
	"io"
	"net/http"
)

// google/pprof's embedded templates have no viewport meta tag and assume a
// 44px-wide desktop toolbar. We cannot restyle them from React when the UI is
// embedded across origins, so inject a small, scoped responsive stylesheet
// into the generated HTML without forking the upstream pprof templates.
//
// Only HTML from the official pprof handlers goes through this adapter. The
// profile's protobuf, DOT endpoint, and graph bridge are left unchanged.
const profilerResponsiveHead = `
<meta name="viewport" content="width=device-width, initial-scale=1">
<style id="yuhaiin-pprof-responsive">
@media (max-width: 720px) {
  html, body { width: 100%; min-width: 0; }
  body { font-size: 14px; }
  .header {
    height: auto; min-height: 0; padding: 8px 10px; gap: 4px 8px;
    flex-wrap: wrap; align-content: flex-start; align-items: center;
  }
  .header > div { margin: 0; min-width: 0; }
  .header .title { flex: 1 0 100%; }
  .header .title h1 { font-size: 20px; margin: 0; }
  .header .menu-item { height: 40px; }
  .header .menu-name { padding: 0 8px; }
  .header .submenu { z-index: 20; max-height: 60vh; overflow: auto; }
  .header .description {
    flex: 1 1 100%; width: auto; min-width: 0; text-align: left;
    white-space: normal; overflow-wrap: anywhere;
  }
  .header > div:has(> #search) { flex: 1 0 100%; order: 2; }
  .header #search {
    display: block; box-sizing: border-box; width: 100%; max-width: none;
    margin: 0; min-height: 40px; font-size: 16px;
  }
  .header .description { order: 3; }
  #detailsbox { max-width: calc(100vw - 20px); right: 10px; top: 48px; }
  #top, #content { max-width: 100%; overflow: auto; -webkit-overflow-scrolling: touch; }
  #top table { width: max-content; min-width: 100%; }
  #top table tr td:nth-child(6) { width: auto; max-width: none; }
  #stack-holder { overflow: auto; -webkit-overflow-scrolling: touch; }
  #stack-chart { min-width: 720px; }
  #current-details { min-height: 36px; padding: 8px; font-size: 13px; }
  #save-dialog, #delete-dialog { width: min(95vw, 360px); max-width: none; }
  .dialog { top: 12vh; }
  #content.source pre, #content pre { overflow-x: auto; max-width: 100%; }
}
</style>
`

type profilerResponsiveWriter struct {
	http.ResponseWriter
}

func (w profilerResponsiveWriter) Write(p []byte) (int, error) {
	// Upstream pprof renders its entire HTML template in one Write. Do not
	// rewrite error responses or arbitrary non-HTML data.
	if !bytes.Contains([]byte(w.Header().Get("Content-Type")), []byte("text/html")) {
		return w.ResponseWriter.Write(p)
	}
	const headEnd = "</head>"
	i := bytes.Index(bytes.ToLower(p), []byte(headEnd))
	if i < 0 || bytes.Contains(p, []byte("id="yuhaiin-pprof-responsive"")) {
		return w.ResponseWriter.Write(p)
	}
	w.Header().Del("Content-Length")
	for _, chunk := range [][]byte{p[:i], []byte(profilerResponsiveHead), p[i:]} {
		n, err := w.ResponseWriter.Write(chunk)
		if err != nil {
			return 0, err
		}
		if n != len(chunk) {
			return 0, io.ErrShortWrite
		}
	}
	return len(p), nil
}
