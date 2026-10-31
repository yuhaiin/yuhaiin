package app

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestManagementResponseContentTypes(t *testing.T) {
	for _, tc := range []struct {
		name, contentType string
		start             func(http.ResponseWriter)
	}{
		{"implicit response", "text/plain; charset=utf-8", func(http.ResponseWriter) {}},
		{"explicit status", "text/plain; charset=utf-8", func(w http.ResponseWriter) { w.WriteHeader(http.StatusOK) }},
		{"flushed response", "text/plain; charset=utf-8", func(w http.ResponseWriter) { w.(http.Flusher).Flush() }},
		{"explicit JSON", "application/json", func(w http.ResponseWriter) { w.Header().Set("Content-Type", "application/json") }},
		{"explicit binary", "application/octet-stream", func(w http.ResponseWriter) { w.Header().Set("Content-Type", "application/octet-stream") }},
		{"explicit HTML", "text/html; charset=utf-8", func(w http.ResponseWriter) { w.Header().Set("Content-Type", "text/html; charset=utf-8") }},
		{"early hint before JSON", "application/json", func(w http.ResponseWriter) {
			w.WriteHeader(http.StatusEarlyHints)
			w.Header().Set("Content-Type", "application/json")
		}},
		{"explicit event stream", "text/event-stream", func(w http.ResponseWriter) {
			w.Header().Set("Content-Type", "text/event-stream")
			w.(http.Flusher).Flush()
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mux := http.NewServeMux()
			HandleFunc(mux, nil, "GET /echo", func(w http.ResponseWriter, r *http.Request) error {
				tc.start(w)
				_, err := io.WriteString(w, r.URL.Query().Get("value"))
				return err
			})
			server := httptest.NewServer(mux)
			defer server.Close()
			const payload = "<script>window.example = true</script>"
			response, err := server.Client().Get(server.URL + "/echo?value=" + url.QueryEscape(payload))
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if response.StatusCode != http.StatusOK {
				t.Fatal("unexpected final response status", response.StatusCode)
			}
			body, err := io.ReadAll(response.Body)
			if err != nil || string(body) != payload {
				t.Fatal("response body changed", err)
			}
			if response.Header.Get("Content-Type") != tc.contentType || response.Header.Get("X-Content-Type-Options") != "nosniff" {
				t.Fatalf("unexpected response headers: type=%q options=%q", response.Header.Get("Content-Type"), response.Header.Get("X-Content-Type-Options"))
			}
		})
	}
}
