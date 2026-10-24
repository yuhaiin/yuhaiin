package configchange_test

import (
	"context"
	"database/sql"
	"encoding/json/v2"
	"errors"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/security/configchange"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
)

type value struct {
	Revision uint64 `json:"revision"`
	Name     string `json:"name"`
}
type fixture struct {
	db     *sql.DB
	j      *configchange.Journal
	active atomic.Uint64
}

func setup(t *testing.T) *fixture {
	t.Helper()
	db, err := sqlite.OpenManagement(t.Context(), filepath.Join(t.TempDir(), "management.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err = db.DB().ExecContext(t.Context(), `CREATE TABLE example_policy(id INTEGER PRIMARY KEY,revision INTEGER,name TEXT);INSERT INTO example_policy VALUES(1,1,'old')`); err != nil {
		t.Fatal(err)
	}
	return &fixture{db: db.DB(), j: configchange.New(db.DB())}
}
func (f *fixture) apply(revision uint64, name string) configchange.Apply {
	return func(ctx context.Context) error {
		if name == "invalid" {
			return configchange.ErrInvalid
		}
		tx, err := configchange.Begin(ctx, f.db, "example")
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback() }()
		var before value
		if err = tx.QueryRowContext(ctx, `SELECT revision,name FROM example_policy WHERE id=1`).Scan(&before.Revision, &before.Name); err != nil {
			return err
		}
		if before.Revision != revision {
			return configchange.ErrConflict
		}
		after := value{Revision: revision + 1, Name: name}
		if _, err = tx.ExecContext(ctx, `UPDATE example_policy SET revision=?,name=? WHERE id=1`, after.Revision, after.Name); err != nil {
			return err
		}
		if err = configchange.RecordValues(ctx, f.db, tx, "example", "policy", after.Revision, before, after, before, after); err != nil {
			return err
		}
		if err = configchange.Commit(ctx, tx); err != nil {
			return err
		}
		f.active.Store(after.Revision)
		return nil
	}
}
func actor(ctx context.Context) context.Context {
	return configchange.WithActor(ctx, configchange.Actor{ID: "operator"})
}
func TestStageValidateCommitAtomicHistoryAndActivation(t *testing.T) {
	f := setup(t)
	ctx := actor(t.Context())
	staged, err := f.j.Stage(ctx, "example", "", "", f.apply(1, "new"))
	if err != nil || staged.State != "staged" {
		t.Fatalf("stage=%+v err=%v", staged, err)
	}
	if f.active.Load() != 0 {
		t.Fatal("staging activated the policy")
	}
	var name string
	if err = f.db.QueryRowContext(ctx, `SELECT name FROM example_policy`).Scan(&name); err != nil || name != "old" {
		t.Fatalf("staging persisted %s: %v", name, err)
	}
	if err = f.j.Validate(ctx, staged.ID, f.apply(1, "new")); err != nil {
		t.Fatal(err)
	}
	restarted := configchange.New(f.db)
	committed, err := restarted.Commit(ctx, staged.ID, f.apply(1, "new"))
	if err != nil || committed.State != "committed" || committed.CommittedBy != "operator" || f.active.Load() != 2 {
		t.Fatalf("commit=%+v active=%d err=%v", committed, f.active.Load(), err)
	}
	if _, err = restarted.Commit(ctx, staged.ID, f.apply(1, "new")); !errors.Is(err, configchange.ErrConflict) {
		t.Fatalf("replayed commit: %v", err)
	}
}
func TestJournalFailureRollsBackTargetAndKeepsDraft(t *testing.T) {
	f := setup(t)
	ctx := actor(t.Context())
	staged, err := f.j.Stage(ctx, "example", "", "", f.apply(1, "new"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.db.ExecContext(ctx, `CREATE TRIGGER break_history BEFORE UPDATE ON configuration_changes BEGIN SELECT RAISE(FAIL,'history unavailable');END`); err != nil {
		t.Fatal(err)
	}
	if _, err = f.j.Commit(ctx, staged.ID, f.apply(1, "new")); err == nil {
		t.Fatal("unaudited target committed")
	}
	current, err := f.j.Get(ctx, staged.ID)
	if err != nil || current.State != "staged" || f.active.Load() != 0 {
		t.Fatalf("draft=%+v active=%d err=%v", current, f.active.Load(), err)
	}
	var revision int
	if err = f.db.QueryRowContext(ctx, `SELECT revision FROM example_policy`).Scan(&revision); err != nil || revision != 1 {
		t.Fatalf("partial target revision=%d err=%v", revision, err)
	}
}
func TestStageConflictAndAuthorizationRevalidation(t *testing.T) {
	f := setup(t)
	ctx := actor(t.Context())
	staged, err := f.j.Stage(ctx, "example", "", "", f.apply(1, "new"))
	if err != nil {
		t.Fatal(err)
	}
	if err = f.apply(1, "concurrent")(ctx); err != nil {
		t.Fatal(err)
	}
	if err = f.j.Validate(ctx, staged.ID, f.apply(1, "new")); !errors.Is(err, configchange.ErrConflict) {
		t.Fatalf("stale validation %v", err)
	}
	if _, err = f.j.Commit(ctx, staged.ID, f.apply(1, "new")); !errors.Is(err, configchange.ErrConflict) {
		t.Fatalf("stale commit %v", err)
	}
	denied := errors.New("authority revoked")
	ctx = configchange.WithActor(t.Context(), configchange.Actor{ID: "operator", Authorize: func(context.Context, *sql.DB, *sql.Tx, string) error { return denied }})
	if _, err = f.j.Stage(ctx, "example", "", "", f.apply(2, "denied")); !errors.Is(err, denied) {
		t.Fatalf("authority: %v", err)
	}
	if f.active.Load() != 2 {
		t.Fatal("failed authorization activated target")
	}
}
func TestBoundsExpiryAndPublicHistoryOmitsPrivatePayloads(t *testing.T) {
	f := setup(t)
	ctx := actor(t.Context())
	for range configchange.MaxStages {
		if _, err := f.j.Stage(ctx, "example", "", "", f.apply(1, "draft")); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.j.Stage(ctx, "example", "", "", f.apply(1, "overflow")); !errors.Is(err, configchange.ErrLimit) {
		t.Fatalf("unbounded stages: %v", err)
	}
	if _, err := f.db.ExecContext(ctx, `UPDATE configuration_changes SET expires_at=1`); err != nil {
		t.Fatal(err)
	}
	for i := range configchange.MaxHistory + 3 {
		if err := f.apply(uint64(i+1), "history")(ctx); err != nil {
			t.Fatal(err)
		}
	}
	all, err := f.j.List(ctx)
	if err != nil || len(all) != configchange.MaxHistory {
		t.Fatalf("history=%d err=%v", len(all), err)
	}
	if _, err := f.j.Stage(ctx, "example", "", "", f.apply(uint64(configchange.MaxHistory+4), "draft")); err != nil {
		t.Fatal(err)
	}
	tx, err := configchange.Begin(ctx, f.db, "example")
	if err != nil {
		t.Fatal(err)
	}
	private := struct {
		Token string `json:"token"`
	}{"private-proof"}
	public := struct {
		Configured bool `json:"configured"`
	}{true}
	if err = configchange.RecordValues(ctx, f.db, tx, "example", "secret", 1, nil, private, nil, public); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	all, err = f.j.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(all)
	if strings.Contains(string(encoded), "private-proof") {
		t.Fatal("private payload leaked")
	}
	for _, c := range all {
		if c.ResourceID == "secret" {
			one, err := f.j.Get(ctx, c.ID)
			if err != nil {
				t.Fatal(err)
			}
			encoded, _ = json.Marshal(one)
			if strings.Contains(string(encoded), "private-proof") || !strings.Contains(string(encoded), "configured") {
				t.Fatalf("unsafe metadata %s", encoded)
			}
		}
	}
}
func TestStageRejectsDifferentResourceDatabaseAndInvalidInput(t *testing.T) {
	a, b := setup(t), setup(t)
	ctx := actor(t.Context())
	if _, err := a.j.Stage(ctx, "example", "", "", b.apply(1, "cross-database")); !errors.Is(err, configchange.ErrInvalid) {
		t.Fatalf("cross-store stage %v", err)
	}
	if _, err := a.j.Stage(ctx, "example", "", "", a.apply(1, "invalid")); !errors.Is(err, configchange.ErrInvalid) {
		t.Fatalf("invalid stage %v", err)
	}
	if _, err := configchange.NewDocument("example", "policy", 1, nil, strings.Repeat("x", configchange.MaxPayload+1), nil, nil); !errors.Is(err, configchange.ErrLimit) {
		t.Fatalf("unbounded document %v", err)
	}
}
