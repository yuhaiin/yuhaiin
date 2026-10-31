package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite/configbackup"
)

type privateURLBackupStub struct{ BackupController }

func (privateURLBackupStub) Run(context.Context) error {
	return fmt.Errorf("snapshot: %w", configbackup.ErrPrivateSourceURL)
}

func TestBackupRPCExplainsPrivateSourceRefusal(t *testing.T) {
	handlers := newV2Handlers(V2Services{Backup: privateURLBackupStub{}})
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v2/rpc/backup.run", strings.NewReader("{}"))
	if err := handlers.values[v2BackupRun](w, r); err != nil {
		t.Fatal(err)
	}
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "private_configuration_url") || !strings.Contains(w.Body.String(), "encrypted full recovery backup") {
		t.Fatal("backup refusal did not identify the safe recovery option", w.Code)
	}
}
