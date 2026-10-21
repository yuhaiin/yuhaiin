package sqlite

import (
	"database/sql"
	"path/filepath"
	"testing"
)

func TestFakeIPCountsMigrationAndTransactions(t *testing.T) {
	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "state.db")
	db, err := sql.Open(driverName, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	// Upgrade an existing database with mappings before the counting triggers
	// exist, rather than only testing a new empty schema.
	for _, migration := range migrations[:15] {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, statement := range migration.Statements {
			if _, err := tx.ExecContext(ctx, statement); err != nil {
				_ = tx.Rollback()
				t.Fatal(err)
			}
		}
		if migration.Transform != nil {
			if err := migration.Transform(ctx, tx); err != nil {
				_ = tx.Rollback()
				t.Fatal(err)
			}
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
	insert := `INSERT INTO fakeip_entries(family,prefix,domain,ip,created_at,last_used_at) VALUES(4,'198.18.0.0/16',?, ?,1,1)`
	if _, err := db.ExecContext(ctx, insert, "before.example", []byte{198, 18, 0, 1}); err != nil {
		t.Fatal(err)
	}
	for _, statement := range migrations[15].Statements {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	assertCounts := func() {
		t.Helper()
		var actual, recorded int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM fakeip_entries WHERE family=4 AND prefix='198.18.0.0/16'`).Scan(&actual); err != nil {
			t.Fatal(err)
		}
		if err := db.QueryRowContext(ctx, `SELECT entry_count FROM fakeip_pool_counts WHERE family=4 AND prefix='198.18.0.0/16'`).Scan(&recorded); err != nil {
			t.Fatal(err)
		}
		if actual != recorded {
			t.Fatalf("recorded count %d differs from %d persisted rows", recorded, actual)
		}
	}
	assertCounts()
	if _, err := db.ExecContext(ctx, insert, "after.example", []byte{198, 18, 0, 2}); err != nil {
		t.Fatal(err)
	}
	assertCounts()
	// Upserts update an existing row without incrementing its pool count.
	if _, err := db.ExecContext(ctx, insert+` ON CONFLICT(family,prefix,domain) DO UPDATE SET last_used_at=2`, "after.example", []byte{198, 18, 0, 2}); err != nil {
		t.Fatal(err)
	}
	assertCounts()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM fakeip_entries`); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	assertCounts()
	if _, err := db.ExecContext(ctx, `UPDATE fakeip_entries SET prefix='198.19.0.0/16' WHERE domain='after.example'`); err != nil {
		t.Fatal(err)
	}
	assertCounts()
	if count := queryInt(t, db, `SELECT entry_count FROM fakeip_pool_counts WHERE prefix='198.19.0.0/16'`); count != 1 {
		t.Fatalf("moved entry count = %d", count)
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM fakeip_entries`); err != nil {
		t.Fatal(err)
	}
	assertCounts()
}
