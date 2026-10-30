//go:build linux

package servicehost

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
	"github.com/Asutorufa/yuhaiin/pkg/app/backup/recovery"
	contract "github.com/Asutorufa/yuhaiin/pkg/contract/backup"
	contractrecovery "github.com/Asutorufa/yuhaiin/pkg/contract/backup/recovery"
	contractupdate "github.com/Asutorufa/yuhaiin/pkg/contract/update"
	managementauth "github.com/Asutorufa/yuhaiin/pkg/management/auth"
	managementtls "github.com/Asutorufa/yuhaiin/pkg/management/tls"
	"github.com/Asutorufa/yuhaiin/pkg/migrate"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	backupstore "github.com/Asutorufa/yuhaiin/pkg/store/backup"
)

type recoveryDrillHTTPError struct {
	operation string
	status    int
	code      string
}

func drillUser() bool { return os.Getenv("YUHAIIN_RECOVERY_SYSTEMD_USER") == "1" }

func drillSystemctl(ctx context.Context, args ...string) *exec.Cmd {
	if drillUser() {
		args = append([]string{"--user"}, args...)
	}
	return exec.CommandContext(ctx, "systemctl", args...)
}

func drillUnitPath(t *testing.T) string {
	t.Helper()
	if !drillUser() {
		return "/etc/systemd/system/yuhaiin.service"
	}
	directory := filepath.Join(os.Getenv("HOME"), ".config/systemd/user")
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(directory, "yuhaiin.service")
}

func drillDataPath(name string) string {
	if drillUser() {
		return filepath.Join(os.Getenv("HOME"), name)
	}
	return filepath.Join("/", name)
}

func TestInstalledUserRecoveryAdmission(t *testing.T) {
	if os.Getenv("YUHAIIN_RECOVERY_SYSTEMD_DRILL") != "1" || !drillUser() {
		t.Skip("requires the isolated unprivileged systemd drill")
	}
	directory := t.TempDir()
	t.Setenv("PATH", directory)
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(directory, name), []byte("#!/bin/sh\n"+body+"\n"), 0700); err != nil {
			t.Fatal(err)
		}
	}
	write("systemctl", "[ \"$1\" = --user ] || exit 1\nprintf '%s\\n' "+strconv.Itoa(os.Getpid()))
	write("systemd-run", "exit 0")
	maintainer := NewRecoveryMaintainer(directory)
	write("loginctl", "printf 'no\\n'")
	if ok, reason := maintainer.Supported(); ok || !strings.Contains(reason, "lingering") {
		t.Fatalf("non-lingering manager admitted: %v %q", ok, reason)
	}
	write("loginctl", "printf 'yes\\n'")
	write("systemctl", "printf '1\\n'")
	if ok, _ := maintainer.Supported(); ok {
		t.Fatal("another service PID was admitted")
	}
	write("systemctl", "[ \"$1\" = --user ] || exit 1\nprintf '%s\\n' "+strconv.Itoa(os.Getpid()))
	if ok, reason := maintainer.Supported(); !ok {
		t.Fatalf("own lingering user service rejected: %s", reason)
	}
}

func (e *recoveryDrillHTTPError) Error() string {
	return fmt.Sprintf("RPC %s returned HTTP %d (%s)", e.operation, e.status, e.code)
}

// The runner builds this test and the production executable into an isolated
// systemd container. It never talks to the host service or needs public ACME/S3.
func TestInstalledRecoveryMaintenance(t *testing.T) {
	if os.Getenv("YUHAIIN_RECOVERY_SYSTEMD_DRILL") != "1" {
		t.Skip("use scripts/bench/recovery-maintenance/run.py for the isolated real-service drill")
	}
	directory := drillDataPath("data")
	if (os.Geteuid() != 0) != drillUser() {
		t.Fatal("fixture user does not match the selected service manager")
	}
	if _, err := os.Stat("/run/systemd/container"); err != nil {
		t.Fatal("fixture is not inside a systemd container")
	}
	assetMiB, err := strconv.Atoi(os.Getenv("YUHAIIN_RECOVERY_ASSET_MIB"))
	if os.Getenv("YUHAIIN_RECOVERY_ASSET_MIB") == "" {
		assetMiB, err = 0, nil
	}
	if err != nil || assetMiB < 0 || assetMiB > 1024 {
		t.Fatal("invalid bounded resource fixture size")
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
	options := contract.Option{InstanceName: "isolated-systemd-fixture", Recovery: &contractrecovery.Policy{Target: "s3", Recipient: identity.Recipient().String(), AllowMaintenance: true, KeepCount: 3, KeepDays: 30}}
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
	if err := backupstore.New(db).Save(t.Context(), options); err != nil {
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
	unit := fmt.Sprintf("[Unit]\nDescription=Isolated Yuhaiin recovery fixture\n[Service]\nType=simple\nExecStart=/app/yuhaiin run -path %s -host 127.0.0.1:50051 -eweb %s/web\nRestart=no\n", directory, directory)
	if err := os.WriteFile(drillUnitPath(t), []byte(unit), 0600); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) error {
		output, err := drillSystemctl(t.Context(), args...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("systemctl %v: %w: %s", args, err, strings.TrimSpace(string(output)))
		}
		return nil
	}
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
			var body struct {
				Error struct {
					Code string `json:"code"`
				} `json:"error"`
			}
			_ = json.UnmarshalRead(io.LimitReader(response.Body, 16<<10), &body)
			return &recoveryDrillHTTPError{operation: operation, status: response.StatusCode, code: body.Error.Code}
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
	requestCapture := func() contractrecovery.Backup {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for {
			var item contractrecovery.Backup
			err := rpc(t.Context(), "backup.recovery.create", contractrecovery.BackupRequest{ConfirmMaintenance: true}, &item)
			if err == nil {
				return item
			}
			if rejected, ok := errors.AsType[*recoveryDrillHTTPError](err); ok {
				// This specific rejection occurs before enqueuing any job. An
				// uncertain disconnect after submission is never replayed.
				if rejected.status == http.StatusConflict && rejected.code == "backup_busy" && time.Now().Before(deadline) {
					time.Sleep(10 * time.Millisecond)
					continue
				}
				t.Fatal(err)
			}
			return item
		}
	}
	var status contractrecovery.BackupStatus
	wait("initial service readiness", func() bool { return rpc(t.Context(), "backup.recovery.status", struct{}{}, &status) == nil })
	if !status.Supported {
		t.Fatal("real service does not recognize its own systemd owner")
	}
	var updateHistory contractupdate.HistoryResult
	if err := rpc(t.Context(), "update.history", struct{}{}, &updateHistory); err != nil || updateHistory.Recovery == nil || !updateHistory.Recovery.Supported {
		t.Fatalf("real service does not recognize protected updates: %v", err)
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
		out, err := drillSystemctl(t.Context(), "show", unit, "--property=MainPID", "--value").Output()
		if err != nil {
			return 0
		}
		value, _ := strconv.Atoi(strings.TrimSpace(string(out)))
		return value
	}
	before := pid("yuhaiin.service")
	// The service can stop between persisting the request and the response.
	requestCapture()
	var completed contractrecovery.Backup
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
	archivePath := filepath.Join(directory, ".recovery-archives", completed.ID+".yhb")
	if err := os.Remove(archivePath); err != nil {
		t.Fatal(err)
	}
	if err := rpc(t.Context(), "backup.recovery.status", struct{}{}, &status); err != nil || len(status.Items) == 0 || status.Items[0].LocalState != "missing" {
		t.Fatal("missing local S3 archive was not reported", err)
	}
	retrieveRequest := contractrecovery.RetrieveRequest{ID: completed.ID, ConfirmDownload: true, ConfirmReplace: true}
	retrievalBody, err := json.Marshal(retrieveRequest)
	if err != nil {
		t.Fatal(err)
	}
	retrieveDenied, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://localhost:50051/api/v2/rpc/backup.recovery.retrieve", bytes.NewReader(retrievalBody))
	if err != nil {
		t.Fatal(err)
	}
	retrieveDenied.Header.Set("Authorization", "Session "+readerSession.Secret)
	deniedRetrieval, err := client.Do(retrieveDenied)
	if err != nil {
		t.Fatal(err)
	}
	_ = deniedRetrieval.Body.Close()
	if deniedRetrieval.StatusCode != http.StatusForbidden {
		t.Fatal("read-only principal retrieved an S3 archive")
	}
	retrievalPID := pid("yuhaiin.service")
	var retrieved contractrecovery.Backup
	if err := rpc(t.Context(), "backup.recovery.retrieve", retrieveRequest, &retrieved); err != nil {
		t.Fatal(err)
	}
	if retrieved.LocalState != "present" || retrieved.Retrieval != "verified" || retrieved.ArchiveCheck != "" || pid("yuhaiin.service") != retrievalPID {
		t.Fatal("S3 retrieval did not recover the ciphertext without activating the deployment")
	}
	var manifest contractrecovery.Manifest
	if err := rpc(t.Context(), "backup.recovery.verify", contractrecovery.VerifyRequest{ID: completed.ID, Identity: identity.String()}, &manifest); err != nil {
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
	// Import/preview runs while the real service and SQLite owners stay active.
	// The private input is sent only in an authenticated bounded HTTPS body.
	previewPID := pid("yuhaiin.service")
	upload := func(secret string) (contractrecovery.Import, int, error) {
		var item contractrecovery.Import
		archive, err := os.Open(archivePath)
		if err != nil {
			return item, 0, err
		}
		defer archive.Close()
		request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://localhost:50051/api/v2/backup/recovery/imports", archive)
		if err != nil {
			return item, 0, err
		}
		request.ContentLength = completed.Size
		request.Header.Set("Content-Type", "application/octet-stream")
		request.Header.Set("Authorization", "Session "+secret)
		response, err := client.Do(request)
		if err != nil {
			return item, 0, err
		}
		defer response.Body.Close()
		if response.StatusCode == 200 {
			err = json.UnmarshalRead(io.LimitReader(response.Body, 2<<20), &item)
		}
		return item, response.StatusCode, err
	}
	if _, code, err := upload(readerSession.Secret); err != nil || code != http.StatusForbidden {
		t.Fatal("read-only principal uploaded recovery identity material", code, err)
	}
	statusRequest, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://localhost:50051/api/v2/rpc/backup.recovery.restore.status", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	statusRequest.Header.Set("Content-Type", "application/json")
	statusRequest.Header.Set("Authorization", "Session "+readerSession.Secret)
	statusResponse, err := client.Do(statusRequest)
	if err != nil {
		t.Fatal(err)
	}
	_ = statusResponse.Body.Close()
	if statusResponse.StatusCode != http.StatusForbidden {
		t.Fatal("read-only principal read restore metadata", statusResponse.StatusCode)
	}
	var restoreStatus contractrecovery.RestoreStatus
	if err := rpc(t.Context(), "backup.recovery.restore.status", struct{}{}, &restoreStatus); err != nil || restoreStatus.Result != nil {
		t.Fatal("ordinary backup invented a restore result", err)
	}
	imported, code, err := upload(session.Secret)
	if err != nil || code != http.StatusOK || imported.State != "uploaded" {
		t.Fatal("authenticated ciphertext import failed", code, err)
	}
	var previewed contractrecovery.Import
	if err := rpc(t.Context(), "backup.recovery.import.preview", contractrecovery.ImportPreviewRequest{ID: imported.ID, Mode: "original", Identity: identity.String()}, &previewed); err != nil {
		t.Fatal(err)
	}
	if previewed.Preview == nil || previewed.Preview.Manifest.ID != completed.BackupID || previewed.Preview.TargetInstanceID != completed.InstanceID || len(previewed.Preview.Files) == 0 || pid("yuhaiin.service") != previewPID {
		t.Fatal("preview differs from the authenticated backup or restarted the active service")
	}
	if err := rpc(t.Context(), "backup.recovery.import.discard", struct {
		ID      string `json:"id"`
		Confirm bool   `json:"confirm"`
	}{imported.ID, true}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(directory, ".recovery-imports", imported.ID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("discard retained private preview staging", err)
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
	second := requestCapture()
	pendingID := second.ID
	// Preserve bounded, non-secret observations when this particular wait
	// times out. The outer harness collects the journal only after later drills
	// finish, by which time the relevant entries may have been displaced.
	var observed struct {
		waiting, sawID                    bool
		polls, databaseErrors, killErrors int
		phase, errorCode                  string
		servicePID, helperPID             int
	}
	observed.waiting = true
	t.Cleanup(func() {
		if t.Failed() && observed.waiting {
			t.Logf("capture fault injection: polls=%d sawID=%t databaseErrors=%d phase=%q errorCode=%q servicePID=%d helperPID=%d killErrors=%d",
				observed.polls, observed.sawID, observed.databaseErrors, observed.phase, observed.errorCode, observed.servicePID, observed.helperPID, observed.killErrors)
		}
	})
	wait("interruptible real helper", func() bool {
		observed.polls++
		raw, err := sql.Open(sqlite.DriverName(), "file:"+filepath.Join(directory, "state.db")+"?mode=ro")
		if err != nil {
			observed.databaseErrors++
			return false
		}
		defer raw.Close()
		if pendingID == "" {
			_ = raw.QueryRow("SELECT id FROM backup_recovery_history WHERE id<>? ORDER BY created_at DESC LIMIT 1", completed.ID).Scan(&pendingID)
		}
		if pendingID == "" {
			return false
		}
		observed.sawID = true
		var phase string
		if err := raw.QueryRow("SELECT state FROM backup_recovery_history WHERE id=?", pendingID).Scan(&phase); err != nil {
			observed.databaseErrors++
			return false
		}
		observed.phase = phase
		if phase == "failed" {
			var data string
			if raw.QueryRow("SELECT data_json FROM backup_recovery_history WHERE id=?", pendingID).Scan(&data) == nil {
				var item contractrecovery.Backup
				if json.Unmarshal([]byte(data), &item) == nil {
					observed.errorCode = item.ErrorCode
				}
			}
		}
		if phase != "capturing" {
			return false
		}
		observed.servicePID = pid("yuhaiin.service")
		observed.helperPID = pid("yuhaiin-recovery-" + pendingID + ".service")
		if observed.servicePID != 0 || observed.helperPID == 0 {
			return false
		}
		// Kill the helper's main process. A whole-cgroup kill can report an
		// auxiliary-thread ESRCH/EIO after the main process already died, hiding
		// the successful fault injection from this readiness predicate.
		if err := run("kill", "--kill-whom=main", "--signal=KILL", "yuhaiin-recovery-"+pendingID+".service"); err != nil {
			observed.killErrors++
			return false
		}
		return true
	})
	observed.waiting = false
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
	if err := os.Remove(filepath.Join(web, "crash-window.bin")); err != nil {
		t.Fatal(err)
	}
	// Restore the actual first archive over a changed live deployment. Neither
	// service-manager Start nor an HTTP disconnect establishes restore success:
	// the real startup journal and reopened management API must agree.
	var changed contract.Option
	if err := rpc(t.Context(), "backup.config.get", struct{}{}, &changed); err != nil {
		t.Fatal(err)
	}
	changed.InstanceName = "must-be-replaced-by-recovery"
	if err := rpc(t.Context(), "backup.config.put", changed, &changed); err != nil {
		t.Fatal(err)
	}
	imported, code, err = upload(session.Secret)
	if err != nil || code != http.StatusOK {
		t.Fatal("restore fixture upload failed", code, err)
	}
	if err := rpc(t.Context(), "backup.recovery.import.preview", contractrecovery.ImportPreviewRequest{ID: imported.ID, Mode: "original", Identity: identity.String()}, &previewed); err != nil {
		t.Fatal(err)
	}
	if previewed.Preview == nil || previewed.PreviewID == "" {
		t.Fatal("restore preview has no immutable revision")
	}
	restoreRequest := contractrecovery.ImportActivateRequest{ID: imported.ID, ConfirmPreviewID: previewed.PreviewID, ConfirmBackupID: previewed.Preview.Manifest.ID,
		ConfirmSourceInstanceID: previewed.Preview.Manifest.InstanceID, ConfirmTargetInstanceID: previewed.Preview.TargetInstanceID, ConfirmResultInstanceID: previewed.Preview.InstanceID,
		ConfirmMaintenance: true, ConfirmStartupChanges: true, ConfirmSourceStopped: true, ConfirmCredentialRevival: true, ConfirmIdentityReplacement: true}
	before = pid("yuhaiin.service")
	invalid := restoreRequest
	invalid.ConfirmCredentialRevival = false
	if err := rpc(t.Context(), "backup.recovery.import.activate", invalid, nil); err == nil || pid("yuhaiin.service") != before {
		t.Fatal("missing destructive consent restarted the service")
	}
	body, err := json.Marshal(restoreRequest)
	if err != nil {
		t.Fatal(err)
	}
	deniedRequest, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://localhost:50051/api/v2/rpc/backup.recovery.import.activate", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	deniedRequest.Header.Set("Content-Type", "application/json")
	deniedRequest.Header.Set("Authorization", "Session "+readerSession.Secret)
	deniedResponse, err := client.Do(deniedRequest)
	if err != nil {
		t.Fatal(err)
	}
	_ = deniedResponse.Body.Close()
	if deniedResponse.StatusCode != http.StatusForbidden || pid("yuhaiin.service") != before {
		t.Fatal("read-only principal activated a destructive restore", deniedResponse.StatusCode)
	}
	if err := rpc(t.Context(), "backup.recovery.import.activate", restoreRequest, nil); err != nil {
		if _, rejected := errors.AsType[*recoveryDrillHTTPError](err); rejected {
			t.Fatal(err)
		}
		// A single uncertain submission is observed, never replayed.
	}
	wait("actual Web activation, controlled startup and restored authentication", func() bool {
		if rpc(t.Context(), "backup.recovery.restore.status", struct{}{}, &restoreStatus) != nil {
			return false
		}
		return restoreStatus.Result != nil && restoreStatus.Result.State == "committed" && restoreStatus.Result.TransactionID == previewed.PreviewID
	})
	if pid("yuhaiin.service") == before {
		t.Fatal("restore did not actually stop/restart the installed service")
	}
	var restored contract.Option
	if err := rpc(t.Context(), "backup.config.get", struct{}{}, &restored); err != nil || restored.InstanceName != "isolated-systemd-fixture" {
		t.Fatal("reopened configuration did not come from the archive", err)
	}
	wait("committed restore staging cleanup", func() bool {
		_, err := os.Lstat(filepath.Join(directory, ".recovery-imports", imported.ID))
		return errors.Is(err, os.ErrNotExist)
	})
	if assetMiB > 0 {
		// A committed application transaction can precede the transient unit's
		// ExecStopPost. Wait for that exact owner before beginning a separate
		// operator-controlled stop; otherwise its final Start cancels the Stop.
		wait("preceding restore helper completion", func() bool {
			output, _ := drillSystemctl(t.Context(), "show", "yuhaiin-restore-"+imported.ID+".service", "--property=ActiveState", "--value").Output()
			state := strings.TrimSpace(string(output))
			return state == "inactive" || state == "failed"
		})
		measureOfflineRecovery(t, assetMiB, directory, web, identity, run, func() bool {
			var value contract.Option
			return rpc(t.Context(), "backup.config.get", struct{}{}, &value) == nil && value.InstanceName == "isolated-systemd-fixture"
		})
	}

	// Clone activation must actually replace machine identity and invalidate the
	// old management session. Its new administrator bootstrap stays local.
	oldTLS, err := os.ReadFile(filepath.Join(directory, "management-tls.pem"))
	if err != nil {
		t.Fatal(err)
	}
	imported, code, err = upload(session.Secret)
	if err != nil || code != http.StatusOK {
		t.Fatal("clone fixture upload failed", code, err)
	}
	if err := rpc(t.Context(), "backup.recovery.import.preview", contractrecovery.ImportPreviewRequest{ID: imported.ID, Mode: "clone", Identity: identity.String()}, &previewed); err != nil {
		t.Fatal(err)
	}
	if previewed.Preview == nil || previewed.Preview.InstanceID == completed.InstanceID {
		t.Fatal("clone preview reused source identity")
	}
	cloneRequest := contractrecovery.ImportActivateRequest{ID: imported.ID, ConfirmPreviewID: previewed.PreviewID, ConfirmBackupID: previewed.Preview.Manifest.ID,
		ConfirmSourceInstanceID: previewed.Preview.Manifest.InstanceID, ConfirmTargetInstanceID: previewed.Preview.TargetInstanceID, ConfirmResultInstanceID: previewed.Preview.InstanceID,
		ConfirmMaintenance: true, ConfirmStartupChanges: true, ConfirmIdentityReplacement: true, ConfirmCloneEnrollment: true}
	before = pid("yuhaiin.service")
	if err := rpc(t.Context(), "backup.recovery.import.activate", cloneRequest, nil); err != nil {
		if _, rejected := errors.AsType[*recoveryDrillHTTPError](err); rejected {
			t.Fatal(err)
		}
	}
	wait("actual clone startup commit", func() bool {
		status, err := recovery.RestoreStatus(t.Context(), directory)
		return err == nil && status.Result != nil && status.Result.State == "committed" && status.Result.TransactionID == cloneRequest.ConfirmPreviewID && status.Result.InstanceID == cloneRequest.ConfirmResultInstanceID
	})
	if pid("yuhaiin.service") == before {
		t.Fatal("clone restore did not restart the service")
	}
	newTLS, err := os.ReadFile(filepath.Join(directory, "management-tls.pem"))
	if err != nil || bytes.Equal(oldTLS, newTLS) {
		t.Fatal("clone reused the self-signed management identity", err)
	}
	cloneRoots := x509.NewCertPool()
	if !cloneRoots.AppendCertsFromPEM(newTLS) {
		t.Fatal("clone did not publish a valid management certificate")
	}
	cloneTransport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: cloneRoots, MinVersion: tls.VersionTLS12}}
	defer cloneTransport.CloseIdleConnections()
	cloneClient := &http.Client{Transport: cloneTransport, Timeout: 3 * time.Second}
	setupResponse, err := cloneClient.Get("https://localhost:50051/api/v2/auth/setup")
	if err != nil {
		t.Fatal(err)
	}
	var setup struct {
		Required bool `json:"required"`
	}
	setupErr := json.UnmarshalRead(io.LimitReader(setupResponse.Body, 16<<10), &setup)
	_ = setupResponse.Body.Close()
	if setupErr != nil || setupResponse.StatusCode != http.StatusOK || !setup.Required {
		t.Fatal("clone did not require fresh administrator enrollment", setupResponse.StatusCode, setupErr)
	}
	staleRequest, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://localhost:50051/api/v2/rpc/backup.recovery.status", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	staleRequest.Header.Set("Content-Type", "application/json")
	staleRequest.Header.Set("Authorization", "Session "+session.Secret)
	staleResponse, err := cloneClient.Do(staleRequest)
	if err != nil {
		t.Fatal(err)
	}
	_ = staleResponse.Body.Close()
	if staleResponse.StatusCode != http.StatusUnauthorized {
		t.Fatal("cloned deployment retained the source management session", staleResponse.StatusCode)
	}
	wait("clone private staging cleanup", func() bool {
		_, err := os.Lstat(filepath.Join(directory, ".recovery-imports", imported.ID))
		return errors.Is(err, os.ErrNotExist)
	})

}
