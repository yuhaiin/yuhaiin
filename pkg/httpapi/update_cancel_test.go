package httpapi

import (
	"context"
	managementpermission "github.com/Asutorufa/yuhaiin/pkg/management/permission"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type updateCancelStub struct {
	UpdateController
	calls int
}

func (s *updateCancelStub) Cancel(context.Context, string) error { s.calls++; return nil }
func TestUpdateCancellationRequiresPermissionConsentAndBoundedInput(t *testing.T) {
	if v2Permissions[v2UpdateCancel] != managementpermission.UpdateManage {
		t.Fatal("cancellation lacks update management permission")
	}
	for _, body := range []string{`{"id":"operation","confirm":true}`, `{"id":"operation"}`, `{"id":"` + strings.Repeat("x", 5<<10) + `","confirm":true}`} {
		owner := new(updateCancelStub)
		handler := newV2Handlers(V2Services{Update: owner})
		request := httptest.NewRequest(http.MethodPost, "/api/v2/rpc/update.cancel", strings.NewReader(body))
		response := httptest.NewRecorder()
		if err := handler.values[v2UpdateCancel](response, request); err != nil {
			t.Fatal(err)
		}
		if body == `{"id":"operation","confirm":true}` {
			if response.Code != http.StatusOK || owner.calls != 1 {
				t.Fatal("confirmed cancellation not dispatched", response.Code)
			}
		} else if response.Code == http.StatusOK || owner.calls != 0 {
			t.Fatal("unconfirmed or oversized cancellation dispatched", response.Code)
		}
	}
}
