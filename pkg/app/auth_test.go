package app

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestLegacyBasicAuthUsesIndependentVerifiers(t *testing.T) {
	first := NewAuth("administrator", "a legacy password")
	second := NewAuth("administrator", "a legacy password")
	if first.Password == second.Password {
		t.Fatal("equal passwords produced reusable unsalted verifiers")
	}
	for _, auth := range []*Auth{first, second} {
		for _, tc := range []struct {
			username, password string
			accepted           bool
		}{
			{"administrator", "a legacy password", true},
			{"other", "a legacy password", false},
			{"administrator", "wrong password", false},
			{"other", "wrong password", false},
		} {
			if got := auth.Auth(tc.password, tc.username); got != tc.accepted {
				t.Fatalf("credential acceptance = %v, want %v", got, tc.accepted)
			}
		}
	}
}

func TestLegacyBasicAuthCanceledRequest(t *testing.T) {
	auth := NewAuth("administrator", "a legacy password")
	called := false
	mux := http.NewServeMux()
	HandleFunc(mux, auth, "GET /protected", func(http.ResponseWriter, *http.Request) error {
		called = true
		return nil
	})
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	request := httptest.NewRequestWithContext(ctx, http.MethodGet, "/protected", nil)
	request.SetBasicAuth("administrator", "a legacy password")
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	if called || response.Code != http.StatusUnauthorized {
		t.Fatal("canceled request was authenticated", response.Code, called)
	}
}

func TestLegacyBasicAuthCancellationWhileAdmissionIsFull(t *testing.T) {
	auth := NewAuth("administrator", "a legacy password")
	// Hold the bounded derivation admission, independently of machine speed.
	for range cap(auth.verificationSlots) {
		auth.verificationSlots <- struct{}{}
	}
	defer func() {
		for range cap(auth.verificationSlots) {
			<-auth.verificationSlots
		}
	}()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	started := make(chan struct{})
	result := make(chan bool, 1)
	go func() {
		close(started)
		result <- auth.authenticate(ctx, "a legacy password", "administrator")
	}()
	<-started
	cancel()
	select {
	case accepted := <-result:
		if accepted {
			t.Fatal("canceled queued credentials were accepted")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("canceled verification remained blocked on admission")
	}
}

func TestLegacyBasicAuthHTTPCompatibility(t *testing.T) {
	auth := NewAuth("administrator", "a legacy password")
	mux := http.NewServeMux()
	called := false
	HandleFunc(mux, auth, "/protected", func(w http.ResponseWriter, _ *http.Request) error {
		called = true
		w.WriteHeader(http.StatusAccepted)
		return nil
	})
	for _, tc := range []struct {
		method, username, password string
		status                     int
	}{
		{http.MethodGet, "administrator", "a legacy password", http.StatusAccepted},
		{http.MethodGet, "other", "a legacy password", http.StatusUnauthorized},
		{http.MethodGet, "administrator", "wrong password", http.StatusUnauthorized},
		{http.MethodGet, "", "", http.StatusUnauthorized},
		{http.MethodOptions, "", "", http.StatusNoContent},
	} {
		called = false
		request := httptest.NewRequestWithContext(t.Context(), tc.method, "/protected", nil)
		if tc.username != "" {
			request.SetBasicAuth(tc.username, tc.password)
		}
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		if response.Code != tc.status || called != (tc.status == http.StatusAccepted) {
			t.Fatalf("method=%s status=%d called=%v, want status=%d", tc.method, response.Code, called, tc.status)
		}
	}
	var absent *Auth
	if absent.Auth("", "") || new(Auth).Auth("", "") {
		t.Fatal("uninitialized verifier accepted credentials")
	}
	// Retaining the public fields does not authorize importing the old fast hash.
	if (&Auth{Username: auth.Username, Password: auth.Password}).Auth("a legacy password", "administrator") {
		t.Fatal("verifier without its process-local salt was accepted")
	}
}

func BenchmarkLegacyBasicAuth(b *testing.B) {
	auth := NewAuth("administrator", "a legacy password")
	b.ReportAllocs()
	for b.Loop() {
		if !auth.Auth("a legacy password", "administrator") {
			b.Fatal("configured credentials were rejected")
		}
	}
}
