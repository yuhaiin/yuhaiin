package manager

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestRenewalCertificateIDMatchesRFC9773(t *testing.T) {
	key, err := hex.DecodeString("69885b6b87464041e1b37b847ba0ae2cde01c8d4")
	if err != nil {
		t.Fatal(err)
	}
	serial, ok := new(big.Int).SetString("87654321", 16)
	if !ok {
		t.Fatal("serial fixture")
	}
	got, err := renewalCertificateID(&x509.Certificate{AuthorityKeyId: key, SerialNumber: serial})
	if err != nil || got != "aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE" {
		t.Fatal("DER serial leading zero/padding mismatch", got, err)
	}
	if _, err := renewalCertificateID(&x509.Certificate{SerialNumber: serial}); err == nil {
		t.Fatal("missing AKI accepted")
	}
}

func TestARIHTTPSBoundsOriginAndAdvice(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	ca := newTestCA(t)
	cfg := ca.config()
	material := signedMaterial(t, ca, cfg, now, 0x87654321)
	pair, err := ValidateMaterial(cfg, material, now)
	if err != nil {
		t.Fatal(err)
	}
	id, err := renewalCertificateID(pair.Leaf)
	if err != nil {
		t.Fatal(err)
	}
	var foreignCalls atomic.Int32
	foreign := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { foreignCalls.Add(1) }))
	defer foreign.Close()
	for _, mode := range []string{"valid", "past_window", "clamp_short", "clamp_long", "date", "unsupported", "expired", "origin", "redirect", "insecure", "bad_window", "late_window", "missing_retry", "bad_retry", "huge_directory", "huge_response", "rate_limit", "duplicate", "unsafe_explanation"} {
		t.Run(mode, func(t *testing.T) {
			requests := 0
			var server *httptest.Server
			server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				if r.Method != http.MethodGet || r.Header.Get("Authorization") != "" || r.Header.Get("Accept") != "application/json" {
					t.Error("ARI request is not an unsigned JSON GET")
				}
				if r.URL.Path == "/directory" {
					if mode == "huge_directory" {
						_, _ = w.Write([]byte(strings.Repeat(" ", 65<<10)))
						return
					}
					endpoint := server.URL + "/ari"
					switch mode {
					case "unsupported":
						_, _ = w.Write([]byte(`{}`))
						return
					case "origin":
						endpoint = foreign.URL + "/ari"
					case "insecure":
						endpoint = "http://127.0.0.1/ari"
					}
					_ = json.MarshalWrite(w, map[string]string{"renewalInfo": endpoint})
					return
				}
				if r.URL.Path != "/ari/"+id {
					t.Errorf("wrong certificate path %q", r.URL.Path)
				}
				if mode == "redirect" {
					http.Redirect(w, r, foreign.URL+"/ari", http.StatusFound)
					return
				}
				if mode == "rate_limit" {
					w.Header().Set("Retry-After", "300")
					w.WriteHeader(http.StatusTooManyRequests)
					return
				}
				if mode == "huge_response" {
					_, _ = w.Write([]byte(strings.Repeat(" ", 65<<10)))
					return
				}
				if mode == "duplicate" {
					w.Header().Set("Retry-After", "3600")
					_, _ = w.Write([]byte(`{"suggestedWindow":{},"suggestedWindow":{}}`))
					return
				}
				retry := "3600"
				switch mode {
				case "clamp_short":
					retry = "0"
				case "clamp_long":
					retry = "9223372036854775807"
				case "date":
					retry = now.Add(2 * time.Hour).Format(http.TimeFormat)
				case "missing_retry":
					retry = ""
				case "bad_retry":
					retry = "invalid"
				}
				w.Header().Set("Retry-After", retry)
				start, end := now.Add(10*time.Hour), now.Add(12*time.Hour)
				if mode == "bad_window" {
					end = start
				}
				if mode == "late_window" {
					start = pair.Leaf.NotAfter
					end = start.Add(time.Hour)
				}
				if mode == "past_window" {
					start, end = now.Add(-2*time.Hour), now.Add(-time.Hour)
				}
				explanation := server.URL + "/explanation"
				if mode == "unsafe_explanation" {
					explanation = "javascript:alert(1)"
				}
				_ = json.MarshalWrite(w, map[string]any{"suggestedWindow": map[string]time.Time{"start": start, "end": end}, "explanationURL": explanation})
			}))
			defer server.Close()
			config := cfg
			config.DirectoryURL = server.URL + "/directory"
			current := now
			if mode == "expired" {
				current = pair.Leaf.NotAfter
			}
			result, err := FetchRenewalInfo(t.Context(), server.Client(), config, pair, current)
			valid := slices.Contains([]string{"valid", "past_window", "clamp_short", "clamp_long", "date", "unsupported", "unsafe_explanation"}, mode)
			if valid {
				if err != nil {
					t.Fatal(err)
				}
				if result.Supported != (mode != "unsupported") {
					t.Fatal(result)
				}
				delay := time.Hour
				switch mode {
				case "clamp_short":
					delay = time.Minute
				case "clamp_long", "unsupported":
					delay = 24 * time.Hour
				case "date":
					delay = 2 * time.Hour
				}
				if !result.NextCheck.Equal(now.Add(delay)) {
					t.Fatal("Retry-After mismatch", result.NextCheck, delay)
				}
				if mode == "unsafe_explanation" && result.ExplanationURL != "" {
					t.Fatal("unsafe explanation URL retained")
				}
			} else if err == nil {
				t.Fatal("invalid ARI response accepted", result)
			}
			if mode == "expired" && requests != 0 {
				t.Fatal("expired certificate made a request")
			}
			if mode == "unsupported" && requests != 1 {
				t.Fatal("unsupported CA received an ARI request")
			}
			if mode == "rate_limit" {
				e, ok := errors.AsType[*renewalInfoError](err)
				if !ok || e.retryAfter != 5*time.Minute {
					t.Fatal("rate protection lost", err)
				}
			}
			if foreignCalls.Load() != 0 {
				t.Fatal("ARI escaped the configured CA origin")
			}
		})
	}
	untrusted := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("untrusted CA handler reached") }))
	defer untrusted.Close()
	config := cfg
	config.DirectoryURL = untrusted.URL + "/directory"
	if _, err := FetchRenewalInfo(t.Context(), &http.Client{Transport: &http.Transport{}}, config, pair, now); err == nil {
		t.Fatal("untrusted HTTPS accepted")
	}
}

func TestARICancellationStopsNetwork(t *testing.T) {
	now := time.Now()
	ca := newTestCA(t)
	cfg := ca.config()
	pair, err := ValidateMaterial(cfg, signedMaterial(t, ca, cfg, now, 2), now)
	if err != nil {
		t.Fatal(err)
	}
	entered, stopped := make(chan struct{}), make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { close(entered); <-r.Context().Done(); close(stopped) }))
	defer server.Close()
	cfg.DirectoryURL = server.URL + "/directory"
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := FetchRenewalInfo(ctx, server.Client(), cfg, pair, now); done <- err }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("request did not start")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancellation succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("request did not cancel")
	}
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("network request remained active")
	}
}
