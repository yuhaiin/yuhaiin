package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/backup"
	managementpermission "github.com/Asutorufa/yuhaiin/pkg/management/permission"
)

type recoveryRetrievalHTTPStub struct {
	BackupController
	calls   int
	request contract.RecoveryRetrieveRequest
}

func (s *recoveryRetrievalHTTPStub) RetrieveRecoveryBackup(_ context.Context, request contract.RecoveryRetrieveRequest) (contract.RecoveryBackup, error) {
	s.calls++
	s.request = request
	return contract.RecoveryBackup{ID: request.ID, State: "verified", Retrieval: "verified", LocalState: "present"}, nil
}
func TestRecoveryRetrievalRPCIsBoundedAndRequiresBackupManage(t *testing.T) {
	if v2Permissions[v2RecoveryBackupRetrieve] != managementpermission.BackupManage {
		t.Fatal("retrieval lacks BackupManage permission")
	}
	for _, large := range []bool{false, true} {
		owner := new(recoveryRetrievalHTTPStub)
		handlers := newV2Handlers(V2Services{Backup: owner})
		body := `{"id":"fixture","confirmDownload":true,"confirmReplace":true}`
		if large {
			body = `{"id":"` + strings.Repeat("x", 5<<10) + `"}`
		}
		request := httptest.NewRequest(http.MethodPost, "/api/v2/rpc/backup.recovery.retrieve", strings.NewReader(body))
		response := httptest.NewRecorder()
		if err := handlers.values[v2RecoveryBackupRetrieve](response, request); err != nil {
			t.Fatal(err)
		}
		if large {
			if owner.calls != 0 || response.Code == http.StatusOK {
				t.Fatal("oversized request reached retrieval", response.Code)
			}
		} else if response.Code != http.StatusOK || owner.calls != 1 || !owner.request.ConfirmDownload || !owner.request.ConfirmReplace || !strings.Contains(response.Body.String(), `"localState":"present"`) {
			t.Fatal("retrieval request or response lost", response.Code, response.Body.String())
		}
	}
}
