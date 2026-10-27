package backup

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	contractbackup "github.com/Asutorufa/yuhaiin/pkg/contract/backup"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/paths"
	storagesqlite "github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	backupstore "github.com/Asutorufa/yuhaiin/pkg/store/backup"
	"go.uber.org/goleak"
)

func streamingBackup(t *testing.T, handler http.HandlerFunc) (*Backup, *backupstore.Store) {
	t.Helper()
	directory := t.TempDir()
	db, err := storagesqlite.Open(t.Context(), paths.PathGenerator.State(directory))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store := backupstore.New(db.DB())
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	if err := store.Save(t.Context(), contractbackup.Option{InstanceName: "fixture", S3: contractbackup.S3{Enabled: true, EndpointURL: server.URL, Bucket: "backups", AccessKey: "access", SecretKey: "secret"}}); err != nil {
		t.Fatal(err)
	}
	b := New(store, directory, nil, direct.Default)
	t.Cleanup(func() { _ = b.Close() })
	return b, store
}

func TestBackupDownloadVerificationAndSkipUnchanged(t *testing.T) {
	var mu sync.Mutex
	var data []byte
	var corrupt atomic.Bool
	var uploads atomic.Int32
	b, store := streamingBackup(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Method == http.MethodPut {
			data, _ = io.ReadAll(r.Body)
			uploads.Add(1)
			return
		}
		if corrupt.Load() {
			_, _ = w.Write([]byte("corrupt"))
			return
		}
		_, _ = w.Write(data)
	})
	corrupt.Store(true)
	if err := b.Run(t.Context()); err == nil {
		t.Fatal("corrupt downloaded verification was accepted")
	}
	opt, err := store.Get(t.Context())
	if err != nil || opt.LastBackupHash != "" {
		t.Fatal("unverified upload marked successful")
	}
	corrupt.Store(false)
	if err := b.Run(t.Context()); err != nil {
		t.Fatal(err)
	}
	opt, err = store.Get(t.Context())
	if err != nil || opt.LastBackupHash == "" {
		t.Fatal("verified backup hash not recorded")
	}
	if err := b.Run(t.Context()); err != nil {
		t.Fatal(err)
	}
	if uploads.Load() != 2 {
		t.Fatalf("unchanged backup uploaded again: %d", uploads.Load())
	}
	leftovers, err := filepath.Glob(filepath.Join(b.dir, ".state-backup-*"))
	if err != nil || len(leftovers) != 0 {
		t.Fatalf("snapshot leaked: %v, %v", leftovers, err)
	}
}

func TestBackupSettingsAreNotOverwrittenByCompletedUpload(t *testing.T) {
	uploaded := make(chan struct{})
	release := make(chan struct{})
	var data []byte
	b, store := streamingBackup(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			data, _ = io.ReadAll(r.Body)
			return
		}
		close(uploaded)
		<-release
		_, _ = w.Write(data)
	})
	result := make(chan error, 1)
	go func() { result <- b.Run(t.Context()) }()
	select {
	case <-uploaded:
	case err := <-result:
		t.Fatal("backup returned before readback", err)
	case <-time.After(5 * time.Second):
		t.Fatal("upload did not finish")
	}
	opt, err := b.Get(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	opt.InstanceName = "changed"
	if _, err := b.Save(t.Context(), opt); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	got, err := store.Get(t.Context())
	if err != nil || got.InstanceName != "changed" || got.LastBackupHash != "" {
		t.Fatalf("concurrent settings overwritten: %+v, %v", got, err)
	}
}

func TestBackupCloseCancelsManualTransfer(t *testing.T) {
	started := make(chan struct{}, 1)
	b, _ := streamingBackup(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		started <- struct{}{}
		select {
		case <-r.Context().Done():
		case <-t.Context().Done():
		}
	})
	result := make(chan error, 1)
	go func() { result <- b.Run(t.Context()) }()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("backup did not start")
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("close did not cancel manual work: %v", err)
	}
	if err := b.Run(t.Context()); !errors.Is(err, context.Canceled) {
		t.Fatalf("closed backup accepted work: %v", err)
	}
}

func TestBackupRepeatedScheduleChangesDoNotLeak(t *testing.T) {
	dir := t.TempDir()
	db, err := storagesqlite.Open(t.Context(), paths.PathGenerator.State(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	store := backupstore.New(db.DB())
	b := New(store, dir, nil, direct.Default)
	for i := range 100 {
		if _, err := b.Save(t.Context(), contractbackup.Option{InstanceName: "fixture", Interval: uint64(i % 2), S3: contractbackup.S3{Enabled: true}}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := b.Save(t.Context(), contractbackup.Option{Interval: ^uint64(0)}); err == nil {
		t.Fatal("overflowing interval accepted")
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestBackupSnapshotIsPrivateAndCancelled(t *testing.T) {
	b, _ := streamingBackup(t, func(http.ResponseWriter, *http.Request) {})
	snapshot, err := b.snapshotStateDB(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	path := snapshot.Name()
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("snapshot permissions: %v, %v", info, err)
	}
	dir, err := os.Stat(filepath.Dir(path))
	if err != nil || dir.Mode().Perm()&0o077 != 0 {
		t.Fatal("snapshot directory is public")
	}
	if err := snapshot.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("closed snapshot remains")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := b.snapshotStateDB(ctx); err == nil {
		t.Fatal("cancelled SQLite snapshot accepted")
	}
	leftovers, _ := filepath.Glob(filepath.Join(b.dir, ".state-backup-*"))
	if len(leftovers) != 0 {
		t.Fatal("cancelled snapshot leaked")
	}
}
