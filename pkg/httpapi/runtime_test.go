package httpapi

import (
	"context"
	json "encoding/json/v2"
	"net/http/httptest"
	"testing"

	schemaapi "github.com/Asutorufa/yuhaiin/pkg/schema/api"
)

type runtimeStub struct {
	info *schemaapi.RuntimeInfo
	err  error
}

func (r runtimeStub) BuildInfo(context.Context) (*schemaapi.RuntimeInfo, error) {
	return r.info, r.err
}

func TestRuntimeInfo(t *testing.T) {
	handler := RuntimeInfo(runtimeStub{
		info: &schemaapi.RuntimeInfo{
			Version: "v1.0.0",
			Commit:  "abc",
		},
	})

	req := httptest.NewRequest("GET", "/api/v1/info", nil)
	rec := httptest.NewRecorder()

	if err := handler(rec, req); err != nil {
		t.Fatalf("handler returned error: %v", err)
	}

	if rec.Code != 200 {
		t.Fatalf("unexpected status: %d", rec.Code)
	}

	var got schemaapi.RuntimeInfo
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response failed: %v", err)
	}

	if got.Version != "v1.0.0" || got.Commit != "abc" {
		t.Fatalf("unexpected response: %+v", got)
	}
}
