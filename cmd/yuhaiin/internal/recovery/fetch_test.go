package recoverycmd

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"uuid"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/backup"
	contractrecovery "github.com/Asutorufa/yuhaiin/pkg/contract/backup/recovery"
)

func TestRecoveryCLIFetchWorksWithoutDeploymentAndPreservesExistingFile(t *testing.T) {
	var requests atomic.Int32
	content := []byte("ciphertext fixture requiring later authentication")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != http.MethodGet {
			t.Error("fetch mutated object", r.Method)
		}
		_, _ = w.Write(content)
	}))
	defer server.Close()
	directory := t.TempDir()
	config := filepath.Join(directory, "s3.json")
	metadata := filepath.Join(directory, "point.json")
	archive := filepath.Join(directory, "retrieved.yhb")
	options := contract.S3{Enabled: true, EndpointURL: server.URL, Bucket: "fixture", AccessKey: "private-access", SecretKey: "private-secret"}
	data, _ := json.Marshal(options)
	if err := os.WriteFile(config, data, 0600); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(content)
	point := contractrecovery.Backup{ID: uuid.New().String(), BackupID: uuid.New().String(), InstanceID: uuid.New().String(), Target: "s3", Size: int64(len(content)), SHA256: hex.EncodeToString(hash[:])}
	point.ObjectKey = "recovery/" + point.InstanceID + "/" + point.BackupID + ".yhb"
	data, _ = json.Marshal(point)
	if err := os.WriteFile(metadata, data, 0600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	args := []string{"fetch", "-s3-config-file", config, "-metadata-file", metadata, "-archive", archive, "-path", filepath.Join(directory, "does-not-exist")}
	if err := Execute(t.Context(), args, &output); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "private-") || !strings.Contains(output.String(), "ciphertext_verified") {
		t.Fatal("fetch exposed credentials or claimed authentication", output.String())
	}
	actual, err := os.ReadFile(archive)
	if err != nil || !bytes.Equal(actual, content) {
		t.Fatal("fetch wrong file", err)
	}
	before := requests.Load()
	if err := Execute(t.Context(), args, &output); err == nil || requests.Load() != before {
		t.Fatal("existing file replaced or downloaded again", err)
	}
	if _, err := os.Stat(filepath.Join(directory, "state.db")); !os.IsNotExist(err) {
		t.Fatal("offline fetch opened a database", err)
	}
	// Neither parser diagnostics nor overly broad permissions may expose keys.
	if err := os.WriteFile(config, []byte(`{"secretKey":"private-secret",`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Execute(t.Context(), args, &output); err == nil || strings.Contains(err.Error(), "private-secret") {
		t.Fatal("bad JSON leaked a secret", err)
	}
}
