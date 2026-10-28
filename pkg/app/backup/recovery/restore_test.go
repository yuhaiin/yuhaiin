package recovery

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
	"uuid"

	"filippo.io/age"
	testfixture "github.com/Asutorufa/yuhaiin/pkg/app/backup/internal/testfixture"
	contractrecovery "github.com/Asutorufa/yuhaiin/pkg/contract/backup/recovery"
	contractcertificate "github.com/Asutorufa/yuhaiin/pkg/contract/certificate"
	nodecontract "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	managementauth "github.com/Asutorufa/yuhaiin/pkg/management/auth"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tailscale"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	"github.com/Asutorufa/yuhaiin/pkg/store"
	backupstore "github.com/Asutorufa/yuhaiin/pkg/store/backup"
	backuparchive "github.com/Asutorufa/yuhaiin/pkg/store/backup/archive"
	"github.com/Asutorufa/yuhaiin/pkg/store/certificates"
	"github.com/Asutorufa/yuhaiin/pkg/utils/lockfile"
)

func recoveryRestoreArchive(t *testing.T) ([]byte, contractrecovery.Manifest, *age.X25519Identity) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("offline activation needs directory synchronization")
	}
	source, key := testfixture.Deployment(t)
	path := filepath.Join(t.TempDir(), "full.yhb")
	manifest, err := Create(t.Context(), source, path, backuparchive.Encryption{Recipient: key.Recipient().String()}, CreateOptions{ConfirmedMaintenance: true})
	if err != nil {
		t.Fatal(err)
	}
	archive, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return archive, manifest, key
}

func TestRecoveryCloneRotatesMachineKeys(t *testing.T) {
	original := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	document := map[string]any{"type": "wireguard", "wireguard": map[string]any{"secretKey": original}}
	if err := rebindRecoveryDocument(document, func(string) (string, error) { return "", errors.New("no file dependency") }, "clone"); err != nil {
		t.Fatal(err)
	}
	encoded := document["wireguard"].(map[string]any)["secretKey"].(string)
	key, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(key) != 32 || encoded == original || key[0]&7 != 0 || key[31]&128 != 0 || key[31]&64 == 0 {
		t.Fatal("clone reused or malformed the local machine key")
	}
}

func TestRecoveryRestoredTokenScopeAndRevocationRemainEffective(t *testing.T) {
	source, key := testfixture.Deployment(t)
	identity, err := sqlite.OpenManagement(t.Context(), filepath.Join(source, "management.db"))
	if err != nil {
		t.Fatal(err)
	}
	accounts := managementauth.NewStore(identity.DB())
	actor := managementauth.Principal{UserID: "owner", CredentialType: "session", Permissions: managementauth.RolePermissions(managementauth.Admin)}
	token, err := accounts.IssueToken(t.Context(), actor, "owner", []managementauth.Permission{managementauth.SettingsRead}, 0)
	if err != nil {
		t.Fatal(err)
	}
	revoked, err := accounts.IssueToken(t.Context(), actor, "owner", []managementauth.Permission{managementauth.SettingsRead}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identity.DB().ExecContext(t.Context(), "UPDATE management_credentials SET revoked=1 WHERE id=?", revoked.ID); err != nil {
		t.Fatal(err)
	}
	if err := identity.Close(); err != nil {
		t.Fatal(err)
	}
	archivePath := filepath.Join(t.TempDir(), "credentials.yhb")
	manifest, err := Create(t.Context(), source, archivePath, backuparchive.Encryption{Recipient: key.Recipient().String()}, CreateOptions{ConfirmedMaintenance: true})
	if err != nil {
		t.Fatal(err)
	}
	input, err := os.Open(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	target := t.TempDir()
	_, err = Restore(t.Context(), target, input, backuparchive.Decryption{Identity: key.String()}, RestoreOptions{Mode: "original", ConfirmedMaintenance: true,
		ConfirmBackupID: manifest.ID, ConfirmSourceInstanceID: manifest.InstanceID, ConfirmTargetInstanceID: "empty", ConfirmSourceStopped: true, ConfirmCredentialRevival: true})
	if err != nil {
		t.Fatal(err)
	}
	reader, err := sqlite.OpenSnapshotReader(t.Context(), filepath.Join(target, "management.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	restored := managementauth.NewStore(reader)
	principal, err := restored.Authenticate(t.Context(), token.Secret, "token")
	if err != nil || !principal.Allows(managementauth.SettingsRead) || principal.Allows(managementauth.SettingsWrite) {
		t.Fatal("restored token did not retain its effective scope", err)
	}
	if _, err := restored.Authenticate(t.Context(), revoked.Secret, "token"); !errors.Is(err, managementauth.ErrUnauthorized) {
		t.Fatal("a credential revoked before the snapshot became valid")
	}
}

func TestOfflineRecoveryPreviewRestoreAndRollbackExistingInstance(t *testing.T) {
	archive, manifest, key := recoveryRestoreArchive(t)
	target, _ := testfixture.Deployment(t)
	before, err := os.ReadFile(filepath.Join(target, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	preview, err := Preview(t.Context(), target, bytes.NewReader(archive), backuparchive.Decryption{Identity: key.String()}, "original")
	if err != nil {
		t.Fatal(err)
	}
	if preview.TargetInstanceID == manifest.InstanceID || preview.TargetInstanceID == "unreadable" || preview.Runtime.WorkingDirectory != target {
		t.Fatal("wrong target/original identity or unresolved startup inputs", preview)
	}
	after, err := os.ReadFile(filepath.Join(target, "state.db"))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("preview changed live configuration")
	}
	options := RestoreOptions{Mode: "original", ConfirmedMaintenance: true, ConfirmBackupID: manifest.ID, ConfirmSourceInstanceID: manifest.InstanceID, ConfirmTargetInstanceID: preview.TargetInstanceID, ConfirmSourceStopped: true, ConfirmCredentialRevival: true}
	bad := options
	bad.ConfirmCredentialRevival = false
	if _, err := Restore(t.Context(), target, bytes.NewReader(archive), backuparchive.Decryption{Identity: key.String()}, bad); err == nil {
		t.Fatal("older credential validity was restored without confirmation")
	}
	result, err := Restore(t.Context(), target, bytes.NewReader(archive), backuparchive.Decryption{Identity: key.String()}, options)
	if err != nil {
		t.Fatal(err)
	}
	if result.State != "awaiting_startup" || result.InstanceID != manifest.InstanceID {
		t.Fatal("file activation was incorrectly reported as a healthy running service", result)
	}
	identity, err := sqlite.RecoveryInstanceID(t.Context(), filepath.Join(target, "state.db"), false)
	if err != nil || identity != manifest.InstanceID {
		t.Fatal("original instance identity not restored")
	}
	db, err := sqlite.OpenSnapshotReader(t.Context(), filepath.Join(target, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	stored, err := store.NewNodeStore(db).Get(t.Context(), "tls")
	if err != nil || stored.Chain[0].TLSTermination.TLS.Certificates[0].CertFilePath != filepath.Join(target, "site.crt") {
		t.Fatal("relative file dependency was not rebound to restored deployment", stored, err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	files, err := tailscale.RecoveryFiles(target, nodecontract.Tailscale{AuthKey: "tskey-fixture", Hostname: "fixture-host"})
	if err != nil || len(files) != 1 || !strings.Contains(files[0], "v2-") {
		t.Fatal("legacy Tailnet identity did not reach the current owner's namespace", files, err)
	}
	if err := Rollback(target, result.TransactionID, true); err != nil {
		t.Fatal(err)
	}
	after, err = os.ReadFile(filepath.Join(target, "state.db"))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("offline rollback did not restore the exact old database")
	}
	directory, err := tailscale.RecoveryDirectory(target, nodecontract.Tailscale{AuthKey: "tskey-fixture", Hostname: "fixture-host"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("rollback left a new namespace that would bypass legacy identity migration")
	}
}

func TestOfflineRecoveryCloneResetsIdentityCredentialsAndListeners(t *testing.T) {
	archive, manifest, key := recoveryRestoreArchive(t)
	target := t.TempDir()
	result, err := Restore(t.Context(), target, bytes.NewReader(archive), backuparchive.Decryption{Identity: key.String()}, RestoreOptions{Mode: "clone", ConfirmedMaintenance: true,
		ConfirmBackupID: manifest.ID, ConfirmSourceInstanceID: manifest.InstanceID, ConfirmTargetInstanceID: "empty"})
	if err != nil {
		t.Fatal(err)
	}
	if result.InstanceID == manifest.InstanceID || result.State != "awaiting_startup" {
		t.Fatal("clone reused the source deployment identity")
	}
	identity, err := sqlite.OpenSnapshotReader(t.Context(), filepath.Join(target, "management.db"))
	if err != nil {
		t.Fatal(err)
	}
	var count int
	if err := identity.QueryRowContext(t.Context(), "SELECT count(*) FROM management_users").Scan(&count); err != nil || count != 0 {
		t.Fatal("cloned accounts retained source credential verifiers")
	}
	if err := identity.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := sqlite.OpenSnapshotReader(t.Context(), filepath.Join(target, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(t.Context(), "SELECT count(*) FROM gateway_ca").Scan(&count); err != nil || count != 0 {
		t.Fatal("clone retained source MITM CA")
	}
	if err := db.QueryRowContext(t.Context(), "SELECT count(*) FROM nodes_v2 WHERE enabled!=0 OR json_extract(data_json,'$.enabled')=1").Scan(&count); err != nil || count != 0 {
		t.Fatal("clone activated source VPN nodes")
	}
	backups, err := backupstore.New(db).Get(t.Context())
	if err != nil || backups.S3.Enabled || backups.Interval != 0 || backups.S3.AccessKey != "" || backups.S3.SecretKey != "" || backups.InstanceName != result.InstanceID {
		t.Fatal("clone can overwrite the source instance's scheduled S3 backups", err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"management-tls.pem", "zerotier/fixture/1-0000000000000000-0000000000000000.state"} {
		if _, err := os.Stat(filepath.Join(target, path)); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("cloned native/listener identity was installed", path)
		}
	}
	lock, err := lockfile.Acquire(filepath.Join(target, ".configuration.lock"))
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	startup, err := PrepareStartup(target, lock, result.Runtime)
	if err != nil || startup == nil {
		t.Fatal(err)
	}
	if err := startup.Abort(); err != nil {
		t.Fatal(err)
	}
}

func TestRecoveryMonitoringSchedulesPreservedForOriginalAndDisabledForClone(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("offline activation needs directory synchronization")
	}
	source, key := testfixture.BasicDeployment(t)
	db, err := sqlite.Open(t.Context(), filepath.Join(source, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	node := nodecontract.Node{ID: "scheduled", Name: "Scheduled", Origin: "manual", Enabled: true, Chain: []nodecontract.Protocol{{Type: "direct", Direct: &nodecontract.Direct{}}}}
	if err := store.NewNodeStore(db.DB()).Save(t.Context(), node, 0); err != nil {
		t.Fatal(err)
	}
	upload := nodecontract.SpeedSchedule{Enabled: true, Test: nodecontract.SpeedTestRequest{URL: "https://upload.example/test", Direction: "upload", AllowUpload: true}}
	download := nodecontract.SpeedSchedule{Enabled: true, Test: nodecontract.SpeedTestRequest{URL: "https://download.example/test"}}
	monitoring := nodecontract.MonitoringConfig{Probe: nodecontract.ProbeSchedule{Enabled: true}, Speed: download, UploadSpeed: &upload}
	if err := store.NewMonitoringStore(db.DB()).Save(t.Context(), monitoring); err != nil {
		t.Fatal(err)
	}
	automatic, err := store.NewSelectorStore(db.DB()).Save(t.Context(), nodecontract.Selector{Name: "Scheduled", NodeID: node.ID, Policy: &nodecontract.SelectorPolicy{
		Mode: "failover", Candidates: []nodecontract.SelectorCandidate{{NodeID: node.ID, Enabled: true, Weight: 1}},
		Probe: &nodecontract.ProbeSchedule{Enabled: true}, PeriodicSpeed: &download, PeriodicUpload: &upload,
	}})
	if err != nil {
		t.Fatal(err)
	}
	manual, err := store.NewSelectorStore(db.DB()).Save(t.Context(), nodecontract.Selector{Name: "Manual", NodeID: node.ID})
	if err != nil {
		t.Fatal(err)
	}
	certificateStore := certificates.New(db.DB())
	provider, err := certificateStore.SaveProvider(t.Context(), contractcertificate.DNSProvider{ID: uuid.New().String(), Name: "Source zone", Type: "cloudflare", ZoneID: strings.Repeat("a", 32), ZoneName: "example.com"}, certificates.NewSecret([]byte("source-provider-token")))
	if err != nil {
		t.Fatal(err)
	}
	managed, err := certificateStore.Save(t.Context(), contractcertificate.Config{ID: uuid.New().String(), Name: "Source site", Domains: []string{"site.example.com"}, DirectoryURL: contractcertificate.LetsEncryptStaging, Email: "ops@example.com", TermsAccepted: true, AutoRenew: true, Challenge: contractcertificate.Challenge{Type: "dns-01", DNSProviderID: provider.ID}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := certificateStore.AccountKey(t.Context(), managed.Config.DirectoryURL, managed.Config.Email, certificates.NewSecret([]byte("source-account-key"))); err != nil {
		t.Fatal(err)
	}
	// Opaque private-material markers exercise ownership, separately from the
	// manager's real signed-certificate and TLS tests.
	owner := uuid.New().String()
	now := time.Now()
	if ok, err := certificateStore.Acquire(t.Context(), managed.Config.ID, managed.Revision, owner, now, time.Minute); err != nil || !ok {
		t.Fatal(ok, err)
	}
	if err := certificateStore.Complete(t.Context(), managed.Config.ID, managed.Revision, owner, now, contractcertificate.Status{State: "ready"}, &certificates.Material{CertificatePEM: []byte("site certificate marker"), PrivateKey: certificates.NewSecret([]byte("site key marker"))}); err != nil {
		t.Fatal(err)
	}
	if err := certificateStore.AddDNSCleanup(t.Context(), certificates.DNSCleanup{ID: uuid.New().String(), ProviderID: provider.ID, Name: "_acme-challenge.site.example.com", Value: strings.Repeat("a", 43), NotBefore: time.Now().Add(time.Hour).UnixMilli()}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := certificateStore.BindManagement(t.Context(), managed.Config.ID); err != nil {
		t.Fatal(err)
	}
	options, err := backupstore.New(db.DB()).Get(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	options.Recovery = &contractrecovery.Policy{LocalPoints: &contractrecovery.PointRetention{Enabled: true, KeepCount: 2, KeepDays: 30}}
	if err := backupstore.New(db.DB()).Save(t.Context(), options); err != nil {
		t.Fatal(err)
	}
	inputs, err := backupstore.LoadRecoveryRuntime(t.Context(), db.DB())
	if err != nil || inputs == nil {
		t.Fatal("missing runtime", err)
	}
	inputs.ManagementTLS, inputs.ManagedCertificateID = "managed", managed.Config.ID
	if err := backupstore.New(db.DB()).RecordRecoveryRuntime(t.Context(), *inputs); err != nil {
		t.Fatal(err)
	}

	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "schedules.yhb")
	manifest, err := Create(t.Context(), source, path, backuparchive.Encryption{Recipient: key.Recipient().String()}, CreateOptions{ConfirmedMaintenance: true})
	if err != nil {
		t.Fatal(err)
	}
	archive, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"original", "clone"} {
		t.Run(mode, func(t *testing.T) {
			target := t.TempDir()
			_, err := Restore(t.Context(), target, bytes.NewReader(archive), backuparchive.Decryption{Identity: key.String()}, RestoreOptions{Mode: mode, ConfirmedMaintenance: true,
				ConfirmBackupID: manifest.ID, ConfirmSourceInstanceID: manifest.InstanceID, ConfirmTargetInstanceID: "empty", ConfirmSourceStopped: true, ConfirmCredentialRevival: true})
			if err != nil {
				t.Fatal(err)
			}
			restored, err := sqlite.OpenSnapshotReader(t.Context(), filepath.Join(target, "state.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer restored.Close()
			restoredOptions, err := backupstore.New(restored).Get(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if restoredOptions.Recovery == nil || restoredOptions.Recovery.LocalPoints == nil || restoredOptions.Recovery.LocalPoints.Enabled != (mode == "original") {
				t.Fatal("clone inherited local deletion consent", restoredOptions.Recovery)
			}
			certificatesStore := certificates.New(restored)
			restoredInputs, err := backupstore.LoadRecoveryRuntime(t.Context(), restored)
			if err != nil {
				t.Fatal(err)
			}
			refs, err := certificatesStore.References(t.Context(), managed.Config.ID)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "original" && (restoredInputs.ManagementTLS != "managed" || restoredInputs.ManagedCertificateID != managed.Config.ID || len(refs) != 1 || refs[0].Kind != "management") {
				t.Fatal("original managed binding was not preserved", restoredInputs, refs)
			}
			if mode == "clone" && (restoredInputs.ManagementTLS != "self_signed" || restoredInputs.ManagedCertificateID != "" || len(refs) != 0) {
				t.Fatal("clone inherited source management identity", restoredInputs, refs)
			}

			certificate, err := certificatesStore.Get(t.Context(), managed.Config.ID)
			if err != nil || certificate.Config.AutoRenew != (mode == "original") {
				t.Fatal("wrong certificate renewal ownership", certificate, err)
			}
			if mode == "clone" && certificate.Status.State != "disabled" {
				t.Fatal("cloned certificate job remains runnable", certificate.Status)
			}
			dnsProvider, token, err := certificatesStore.Provider(t.Context(), provider.ID)
			if err != nil || dnsProvider.HasCredential != (mode == "original") || token.Empty() != (mode == "clone") {
				t.Fatal("wrong provider identity ownership", dnsProvider, err)
			}
			for _, table := range []string{"managed_certificate_material", "certificate_acme_accounts", "certificate_dns_cleanup"} {
				var count int
				if err := restored.QueryRowContext(t.Context(), "SELECT COUNT(*) FROM "+table).Scan(&count); err != nil {
					t.Fatal(err)
				}
				want := 1
				if mode == "clone" {
					want = 0
				}
				if count != want {
					t.Fatal("source certificate identity/cleanup copied to clone", table, count)
				}
			}
			configuration, err := store.NewMonitoringStore(restored).Get(t.Context())
			enabled := mode == "original"
			if err != nil || configuration.Probe.Enabled != enabled || configuration.Speed.Enabled != enabled || configuration.UploadSpeed == nil || configuration.UploadSpeed.Enabled != enabled {
				t.Fatal("wrong global schedule state", configuration, err)
			}
			value, err := store.NewSelectorStore(restored).Get(t.Context(), automatic.ID)
			if err != nil || value.Policy == nil {
				t.Fatal(value, err)
			}
			p := value.Policy
			if p.Probe == nil || p.Probe.Enabled != enabled || p.PeriodicSpeed == nil || p.PeriodicSpeed.Enabled != enabled || p.PeriodicUpload == nil || p.PeriodicUpload.Enabled != enabled {
				t.Fatal("selector override bypasses disabled clone schedules", p)
			}
			if p.PeriodicUpload.Test.URL != upload.Test.URL || !p.PeriodicUpload.Test.AllowUpload {
				t.Fatal("schedule settings lost", p)
			}
			expectedRevision := automatic.Revision
			if !enabled {
				expectedRevision++
			}
			if value.Revision != expectedRevision {
				t.Fatal("incorrect configuration revision", value.Revision, expectedRevision)
			}
			unchanged, err := store.NewSelectorStore(restored).Get(t.Context(), manual.ID)
			if err != nil || unchanged.Policy != nil || unchanged.Revision != manual.Revision {
				t.Fatal("manual selector changed", unchanged, err)
			}
		})
	}
}
