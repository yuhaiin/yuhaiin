package app

import "net/http"

// The emergency page is served by Core, never by an OTA bundle. It remains
// reachable if a downloaded index.html or JS chunk fails to render.
const frontendRecoveryHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Yuhaiin UI recovery</title></head><body>
<main><h1>Yuhaiin frontend recovery</h1>
<p>This page is part of the Core binary and is independent of downloaded UI files.</p>
<p>Restore the UI packaged in your current yuhaiin binary. The VPN and proxy engine will not restart.</p>
<button id="reset" type="button">Restore bundled UI</button>
<p id="result" role="status"></p></main>
<script src="/__ui_recovery.js" defer></script></body></html>`

const frontendRecoveryScript = `document.getElementById('reset').addEventListener('click', async function () {
  if (!confirm('Discard the selected downloaded UI and restore the bundled interface?')) return;
  const result = document.getElementById('result');
  try {
    const response = await fetch('/api/v2/rpc/frontend.reset', {
      method: 'POST', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' }, body: '{}'
    });
    if (!response.ok) throw new Error('HTTP ' + response.status + '. Sign in as an update administrator first.');
    result.textContent = 'Bundled UI restored. Reloading…';
    location.replace('/');
  } catch (err) {
    result.textContent = 'Recovery failed: ' + String(err) +
      '. Try the regular Core management API with update:manage permission.';
  }
});`

func registerFrontendRecovery(mux *http.ServeMux) {
 mux.HandleFunc("GET /__ui_recovery", func(w http.ResponseWriter, r *http.Request) {
  w.Header().Set("Content-Type", "text/html; charset=utf-8")
  w.Header().Set("Cache-Control", "no-store")
  w.Header().Set("X-Content-Type-Options", "nosniff")
  _, _ = w.Write([]byte(frontendRecoveryHTML))
 })
 mux.HandleFunc("GET /__ui_recovery.js", func(w http.ResponseWriter, r *http.Request) {
  w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
  w.Header().Set("Cache-Control", "no-store")
  w.Header().Set("X-Content-Type-Options", "nosniff")
  _, _ = w.Write([]byte(frontendRecoveryScript))
 })
}
