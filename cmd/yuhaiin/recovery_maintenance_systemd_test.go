//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"filippo.io/age"
	contract "github.com/Asutorufa/yuhaiin/pkg/contract/backup"
	managementauth "github.com/Asutorufa/yuhaiin/pkg/management/auth"
	managementtls "github.com/Asutorufa/yuhaiin/pkg/management/tls"
	"github.com/Asutorufa/yuhaiin/pkg/migrate"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	"github.com/Asutorufa/yuhaiin/pkg/store"
)

// The runner builds this test and the production executable into an isolated
// systemd container. It never talks to the host service or needs public ACME/S3.
func TestInstalledRecoveryMaintenance(t *testing.T) {
	if os.Getenv("YUHAIIN_RECOVERY_SYSTEMD_DRILL") != "1" {
		t.Skip("use scripts/bench/recovery-maintenance/run.py for the isolated real-service drill")
	}
	const directory = "/data"
	if os.Geteuid() != 0 {
		t.Fatal("fixture must run as its container root, not on the host")
	}
	if _, err := os.Stat("/run/systemd/container"); err != nil {
		t.Fatal("fixture is not inside a systemd container")
	}
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	state := migrate.NewStateDB(filepath.Join(directory, "state.db"))
	if err := state.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	db, err := state.SQLDB(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	options := contract.Option{InstanceName: "isolated-systemd-fixture", Recovery: &contract.RecoveryPolicy{Target: "s3", Recipient: identity.Recipient().String(), AllowMaintenance: true, KeepCount: 3, KeepDays: 30}}
	// The object server survives stopping the yuhaiin unit and stores bounded
	// fixture objects on disk, rather than holding an archive-sized byte slice.
	objectDirectory := t.TempDir()
	var objectMu sync.Mutex
	objectServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		objectMu.Lock()
		defer objectMu.Unlock()
		name := sha256.Sum256([]byte(r.URL.Path))
		path := filepath.Join(objectDirectory, hex.EncodeToString(name[:]))
		switch r.Method {
		case http.MethodPut:
			file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
			if err != nil {
				w.WriteHeader(500)
				return
			}
			_, err = io.Copy(file, r.Body)
			err = errors.Join(err, file.Close())
			if err != nil {
				w.WriteHeader(500)
			}
		case http.MethodGet:
			file, err := os.Open(path)
			if err != nil {
				w.WriteHeader(404)
				return
			}
			defer file.Close()
			_, _ = io.Copy(w, file)
		case http.MethodDelete:
			_ = os.Remove(path)
			w.WriteHeader(204)
		default:
			w.WriteHeader(405)
		}
	}))
	defer objectServer.Close()
	options.S3 = contract.S3{Enabled: true, EndpointURL: objectServer.URL, Bucket: "fixture", AccessKey: "fixture-access", SecretKey: "fixture-secret"}
	if err := store.NewBackupStore(db).Save(t.Context(), options); err != nil {
		t.Fatal(err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	management, err := sqlite.OpenManagement(t.Context(), filepath.Join(directory, "management.db"))
	if err != nil {
		t.Fatal(err)
	}
	authStore := managementauth.NewStore(management.DB())
	user, enrollment, err := authStore.CreateUser(t.Context(), "local", "fixture-admin", managementauth.Admin, true)
	if err != nil {
		t.Fatal(err)
	}
	passwords, err := managementauth.NewPasswordService(t.Context(), authStore)
	if err != nil {
		t.Fatal(err)
	}
	derived := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	if err := passwords.Enroll(t.Context(), enrollment.Secret, derived); err != nil {
		t.Fatal(err)
	}
	session, err := passwords.Login(t.Context(), user.Login, derived)
	if err != nil {
		t.Fatal(err)
	}
	readerUser, readerEnrollment, err := authStore.CreateUser(t.Context(), user.ID, "fixture-reader", managementauth.ReadOnly, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := passwords.Enroll(t.Context(), readerEnrollment.Secret, derived); err != nil {
		t.Fatal(err)
	}
	readerSession, err := passwords.Login(t.Context(), readerUser.Login, derived)
	if err != nil {
		t.Fatal(err)
	}
	if err := management.Close(); err != nil {
		t.Fatal(err)
	}
	certificate, _, _, err := managementtls.LoadOrCreate(directory, []string{"localhost"})
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: "localhost"}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	web := filepath.Join(directory, "web")
	if err := os.MkdirAll(web, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(web, "index.html"), []byte("isolated recovery fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	unit := "[Unit]\nDescription=Isolated Yuhaiin recovery fixture\n[Service]\nType=simple\nExecStart=/app/yuhaiin run -path /data -host 127.0.0.1:50051 -eweb /data/web\nRestart=no\n"
	if err := os.WriteFile("/etc/systemd/system/yuhaiin.service", []byte(unit), 0600); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) error { return exec.Command("systemctl", args...).Run() }
	if err := run("daemon-reload"); err != nil {
		t.Fatal(err)
	}
	if err := run("start", "yuhaiin.service"); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = run("stop", "yuhaiin.service") }()
	rpc := func(ctx context.Context, operation string, input, output any) error {
		body, err := json.Marshal(input)
		if err != nil {
			return err
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://localhost:50051/api/v2/rpc/"+operation, bytes.NewReader(body))
		if err != nil {
			return err
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Authorization", "Session "+session.Secret)
		response, err := client.Do(request)
		if err != nil {
			return err
		}
		defer response.Body.Close()
		if response.StatusCode != 200 {
			return fmt.Errorf("RPC %s returned HTTP %d", operation, response.StatusCode)
		}
		if output == nil {
			return nil
		}
		return json.UnmarshalRead(io.LimitReader(response.Body, 2<<20), output)
	}
	wait := func(label string, fn func() bool) {
		t.Helper()
		deadline := time.Now().Add(45 * time.Second)
		for time.Now().Before(deadline) {
			if fn() {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatal(label, "did not complete")
	}
	var status contract.RecoveryBackupStatus
	wait("initial service readiness", func() bool { return rpc(t.Context(), "backup.recovery.status", struct{}{}, &status) == nil })
	if !status.Supported {
		t.Fatal("real service does not recognize its own systemd owner")
	}
	for _, secret := range []string{"", readerSession.Secret} {
		request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://localhost:50051/api/v2/rpc/backup.recovery.status", strings.NewReader("{}"))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/json")
		if secret != "" {
			request.Header.Set("Authorization", "Session "+secret)
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		expected := http.StatusForbidden
		if secret == "" {
			expected = http.StatusUnauthorized
		}
		if response.StatusCode != expected {
			t.Fatal("backup history permission gate was bypassed", response.StatusCode)
		}
	}

	pid := func(unit string) int {
		out, err := exec.Command("systemctl", "show", unit, "--property=MainPID", "--value").Output()
		if err != nil {
			return 0
		}
		value, _ := strconv.Atoi(strings.TrimSpace(string(out)))
		return value
	}
	before := pid("yuhaiin.service")
	var accepted contract.RecoveryBackup
	// The service can stop between persisting the request and the response.
	_ = rpc(t.Context(), "backup.recovery.create", contract.RecoveryBackupRequest{ConfirmMaintenance: true}, &accepted)
	var completed contract.RecoveryBackup
	wait("full snapshot, restart and verified S3 readback", func() bool {
		if rpc(t.Context(), "backup.recovery.status", struct{}{}, &status) != nil {
			return false
		}
		for _, item := range status.Items {
			if item.State == "verified" {
				completed = item
				return true
			}
		}
		return false
	})
	if pid("yuhaiin.service") == before {
		t.Fatal("capture did not actually restart the service")
	}
	if completed.Verification != "s3_ciphertext_readback" || completed.Size < 1 {
		t.Fatal("readback was not recorded")
	}
	var manifest contract.RecoveryManifest
	if err := rpc(t.Context(), "backup.recovery.verify", contract.RecoveryVerifyRequest{ID: completed.ID, Identity: identity.String()}, &manifest); err != nil {
		t.Fatal(err)
	}
	if !manifest.CompleteInventory || manifest.ID != completed.BackupID {
		t.Fatal("authenticated inventory differs from backup record")
	}
	download, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://localhost:50051/api/v2/backup/recovery/"+completed.ID+"/download", nil)
	if err != nil {
		t.Fatal(err)
	}
	download.Header.Set("Authorization", "Session "+readerSession.Secret)
	denied, err := client.Do(download)
	if err != nil {
		t.Fatal(err)
	}
	_ = denied.Body.Close()
	if denied.StatusCode != http.StatusForbidden {
		t.Fatal("read-only principal downloaded private backup material")
	}
	download.Header.Set("Authorization", "Session "+session.Secret)
	response, err := client.Do(download)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.New()
	size, copyErr := io.Copy(sum, response.Body)
	closeErr := response.Body.Close()
	if response.StatusCode != 200 || copyErr != nil || closeErr != nil || size != completed.Size || hex.EncodeToString(sum.Sum(nil)) != completed.SHA256 {
		t.Fatal("download did not match verified ciphertext")
	}
	// Make a real copy/hash/encryption window long enough to kill the independent
	// helper during capture. The sparse file does not occupy memory in this test.
	large, err := os.Create(filepath.Join(web, "crash-window.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if err := large.Truncate(1 << 30); err != nil {
		t.Fatal(err)
	}
	if err := large.Close(); err != nil {
		t.Fatal(err)
	}
	before = pid("yuhaiin.service")
	var second contract.RecoveryBackup
	_ = rpc(t.Context(), "backup.recovery.create", contract.RecoveryBackupRequest{ConfirmMaintenance: true}, &second)
	pendingID := second.ID
	wait("interruptible real helper", func() bool {
		raw, err := sql.Open(sqlite.DriverName(), "file:/data/state.db?mode=ro")
		if err != nil {
			return false
		}
		defer raw.Close()
		if pendingID == "" {
			_ = raw.QueryRow("SELECT id FROM backup_recovery_history WHERE id<>? ORDER BY created_at DESC LIMIT 1", completed.ID).Scan(&pendingID)
		}
		if pendingID == "" {
			return false
		}
		var phase string
		if err := raw.QueryRow("SELECT state FROM backup_recovery_history WHERE id=?", pendingID).Scan(&phase); err != nil || phase != "capturing" {
			return false
		}
		if pid("yuhaiin.service") != 0 || pid("yuhaiin-recovery-"+pendingID+".service") == 0 {
			return false
		}
		return run("kill", "--signal=KILL", "yuhaiin-recovery-"+pendingID+".service") == nil
	})
	wait("ExecStopPost restart after helper death", func() bool {
		if rpc(t.Context(), "backup.recovery.status", struct{}{}, &status) != nil {
			return false
		}
		for _, item := range status.Items {
			if item.ID == pendingID && item.State == "failed" && item.ErrorCode == "capture_interrupted" {
				return true
			}
		}
		return false
	})
	if pid("yuhaiin.service") == before {
		t.Fatal("helper death did not produce a real service restart")
	}
}
