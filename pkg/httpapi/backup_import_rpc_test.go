package httpapi

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/backup"
	managementpermission "github.com/Asutorufa/yuhaiin/pkg/management/permission"
	"github.com/Asutorufa/yuhaiin/pkg/s3"
)

type recoveryImportHTTPStub struct {
	BackupController
	uploads, previews int
}

func (*recoveryImportHTTPStub) RecoveryImports(context.Context) ([]contract.RecoveryImport, error) {
	return []contract.RecoveryImport{}, nil
}
func (s *recoveryImportHTTPStub) UploadRecoveryImport(_ context.Context, body io.ReadCloser, _ int64) (contract.RecoveryImport, error) {
	s.uploads++
	defer body.Close()
	_, err := io.Copy(io.Discard, body)
	return contract.RecoveryImport{ID: "fixture", State: "uploaded"}, err
}
func (s *recoveryImportHTTPStub) PreviewRecoveryImport(context.Context, contract.RecoveryImportPreviewRequest) (contract.RecoveryImport, error) {
	s.previews++
	return contract.RecoveryImport{ID: "fixture", State: "previewed"}, nil
}
func (*recoveryImportHTTPStub) DiscardRecoveryImport(context.Context, string) error { return nil }

func (*recoveryImportHTTPStub) RecoveryRestoreStatus(context.Context) (contract.RecoveryRestoreStatus, error) {
	return contract.RecoveryRestoreStatus{Result: &contract.RecoveryRestoreResult{State: "rolled_back", AdoptStartup: true}}, nil
}

func TestRecoveryRestoreReporterUsesBackupManageAndDistinguishesRollback(t *testing.T) {
	if v2Permissions[v2RecoveryRestoreStatus] != managementpermission.BackupManage {
		t.Fatal("restore metadata is not protected by BackupManage")
	}
	handlers := newV2Handlers(V2Services{Backup: new(recoveryImportHTTPStub)})
	request := httptest.NewRequest(http.MethodPost, "/api/v2/rpc/backup.recovery.restore.status", strings.NewReader("{}"))
	response := httptest.NewRecorder()
	if err := handlers.values[v2RecoveryRestoreStatus](response, request); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"state":"rolled_back"`) || !strings.Contains(response.Body.String(), `"adoptStartup":true`) {
		t.Fatal("restore reporter lost rollback/startup status", response.Code, response.Body.String())
	}
}

func TestRecoveryImportHTTPRejectsWrongTypeAndDeclaredOversizeBeforeReading(t *testing.T) {
	for _, fault := range []string{"type", "size", "none"} {
		t.Run(fault, func(t *testing.T) {
			owner := new(recoveryImportHTTPStub)
			request := httptest.NewRequest(http.MethodPost, "/api/v2/backup/recovery/imports", strings.NewReader("ciphertext"))
			request.Header.Set("Content-Type", "application/octet-stream")
			want := http.StatusOK
			switch fault {
			case "type":
				request.Header.Set("Content-Type", "application/json")
				want = http.StatusUnsupportedMediaType
			case "size":
				request.ContentLength = s3.MaxObjectBytes + 1
				want = http.StatusRequestEntityTooLarge
			}
			response := httptest.NewRecorder()
			if err := recoveryImportUpload(V2Services{Backup: owner})(response, request); err != nil {
				t.Fatal(err)
			}
			if response.Code != want || (fault != "none" && owner.uploads != 0) {
				t.Fatal("invalid upload reached the controller", response.Code, owner.uploads)
			}
		})
	}
}

func TestRecoveryImportPreviewRequestHasIndependentSecretBodyLimit(t *testing.T) {
	owner := new(recoveryImportHTTPStub)
	handlers := newV2Handlers(V2Services{Backup: owner})
	for _, length := range []int{17 << 10, 32} {
		body := `{"id":"fixture","mode":"original","identity":"` + strings.Repeat("x", length) + `"}`
		request := httptest.NewRequest(http.MethodPost, "/api/v2/rpc/backup.recovery.import.preview", strings.NewReader(body))
		response := httptest.NewRecorder()
		if err := handlers.values[v2RecoveryImportPreview](response, request); err != nil {
			t.Fatal(err)
		}
		if length > 16<<10 {
			if response.Code != http.StatusBadRequest || owner.previews != 0 {
				t.Fatal("oversized private input reached the controller")
			}
		} else if response.Code != http.StatusOK || owner.previews != 1 {
			t.Fatal("bounded preview request was rejected")
		}
	}
}
