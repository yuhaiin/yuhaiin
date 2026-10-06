package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/contract/tools"
	"github.com/Asutorufa/yuhaiin/pkg/diagnostics"
)

type diagnosticStub struct {
	err  error
	host string
}

func (s *diagnosticStub) Run(_ context.Context, request tools.DiagnosticRequest) (tools.DiagnosticReport, error) {
	s.host = request.Host
	return tools.DiagnosticReport{SchemaVersion: 1, Host: request.Host, Report: "portable report"}, s.err
}
func TestDiagnosticsRPC(t *testing.T) {
	for _, tc := range []struct {
		name   string
		err    error
		status int
	}{
		{"success", nil, http.StatusOK},
		{"invalid", diagnostics.ErrInvalidHost, http.StatusBadRequest},
		{"busy", diagnostics.ErrBusy, http.StatusTooManyRequests},
		{"internal", errors.New("test failure"), http.StatusInternalServerError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stub := &diagnosticStub{err: tc.err}
			mux := http.NewServeMux()
			RegisterV2(func(pattern string, handler func(http.ResponseWriter, *http.Request) error) {
				mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
					if err := handler(w, r); err != nil {
						t.Error(err)
					}
				})
			}, V2Services{Diagnostics: stub})
			out := httptest.NewRecorder()
			mux.ServeHTTP(out, httptest.NewRequest(http.MethodPost, "/api/v2/rpc/tools.diagnostics", strings.NewReader(`{"host":"example.com"}`)))
			if out.Code != tc.status || stub.host != "example.com" {
				t.Fatalf("code=%d host=%q body=%s", out.Code, stub.host, out.Body.String())
			}
			if tc.status == http.StatusOK && !strings.Contains(out.Body.String(), `"report":"portable report"`) {
				t.Fatal("missing report")
			}
		})
	}
}
