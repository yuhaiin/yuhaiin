package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRemoteHTTPStaticRequestsRedirectToHTTPS(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	redirector := redirectRemoteHTTPToHTTPS(handler, &net.TCPAddr{IP: net.IPv4zero, Port: 50051})

	tests := []struct {
		name       string
		method     string
		path       string
		remoteAddr string
		wantStatus int
		wantTarget string
	}{
		{
			name:       "remote page request",
			method:     http.MethodGet,
			path:       "/settings?tab=routes",
			remoteAddr: "192.0.2.10:43210",
			wantStatus: http.StatusTemporaryRedirect,
			wantTarget: "https://admin.example:50051/settings?tab=routes",
		},
		{
			name:       "remote api request is not redirected",
			method:     http.MethodGet,
			path:       "/api/v2/auth/setup",
			remoteAddr: "192.0.2.10:43210",
			wantStatus: http.StatusNoContent,
		},
		{
			name:       "remote post body is not redirected",
			method:     http.MethodPost,
			path:       "/login",
			remoteAddr: "192.0.2.10:43210",
			wantStatus: http.StatusNoContent,
		},
		{
			name:       "loopback page remains http",
			method:     http.MethodGet,
			path:       "/",
			remoteAddr: "127.0.0.1:43210",
			wantStatus: http.StatusNoContent,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := httptest.NewRequest(tt.method, "http://admin.example:50051"+tt.path, nil)
			request.RemoteAddr = tt.remoteAddr
			response := httptest.NewRecorder()
			redirector.ServeHTTP(response, request)
			if response.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", response.Code, tt.wantStatus)
			}
			if location := response.Header().Get("Location"); location != tt.wantTarget {
				t.Fatalf("Location = %q, want %q", location, tt.wantTarget)
			}
		})
	}
}
