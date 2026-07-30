package http

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/auth"
)

type basicAuthStub struct{}

func (basicAuthStub) AuthBasic(username, password string) (auth.Principal, error) {
	if username == "alice" && password == "secret" {
		return auth.Principal{UserID: "user-1"}, nil
	}
	return auth.Principal{}, errors.New("invalid credential")
}

func TestServeHTTPCentralAuthenticationRejectsMissingAndInvalidCredentials(t *testing.T) {
	server := &Server{authenticator: basicAuthStub{}}
	for _, tt := range []struct {
		name   string
		header string
		status int
	}{
		{name: "missing", status: http.StatusProxyAuthRequired},
		{name: "invalid", header: "Basic YWxpY2U6d3Jvbmc=", status: http.StatusForbidden},
	} {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodConnect, "http://example.com", nil)
			if tt.header != "" {
				req.Header.Set("Proxy-Authorization", tt.header)
			}
			recorder := httptest.NewRecorder()
			server.ServeHTTP(recorder, req)
			if recorder.Code != tt.status {
				t.Fatalf("status = %d, want %d", recorder.Code, tt.status)
			}
		})
	}
}
