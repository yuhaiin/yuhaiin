package sqlite

import (
	"context"
	"database/sql"
	"path/filepath"
	"slices"
	"testing"
)

func TestSecurityAuditMigrationInterruptionRetainsIdentitiesAndHistory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "management.db")
	old, err := open(t.Context(), path, "management", func(ctx context.Context, db *sql.DB) error {
		if err := bootstrapBase(ctx, db); err != nil {
			return err
		}
		for _, migration := range []Migration{managementAuthMigration, managementInitializationMigration, proxyCredentialsMigration, managementOAuthMigration, managementAuditMigration, managementSSTPMigration, managementPasskeyMigration, trafficGroupsMigration, trafficAccessMigration, resourceGovernanceMigration, managementRolesMigration, managementOIDCMigration} {
			if err := applyMigration(ctx, db, migration); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{`INSERT INTO management_users(id,login,role,disabled,created_at,updated_at,generation,client_salt,credential) VALUES('u','admin','admin',0,1,1,1,zeroblob(16),'private-record')`, `INSERT INTO management_security_events(id,occurred_at,event,actor_id,subject_id) VALUES(123,1,'legacy.updated','u','legacy')`} {
		if _, err = old.DB().ExecContext(t.Context(), statement); err != nil {
			t.Fatal(err)
		}
	}
	broken := managementSecurityAuditMigration
	broken.Statements = append(slices.Clone(broken.Statements), "INTERRUPTED MIGRATION")
	if err = applyMigration(t.Context(), old.DB(), broken); err == nil {
		t.Fatal("interrupted migration committed")
	}
	if _, err = old.DB().ExecContext(t.Context(), `SELECT auth_method FROM management_security_events`); err == nil {
		t.Fatal("partial schema survived")
	}
	if err = old.Close(); err != nil {
		t.Fatal(err)
	}
	var instance string
	for range 2 {
		db, err := OpenManagement(t.Context(), path)
		if err != nil {
			t.Fatal(err)
		}
		if queryInt(t, db.DB(), `PRAGMA synchronous`) != 2 {
			t.Fatal("management ledger requires FULL synchronous commits")
		}
		var current, proof string
		if err = db.DB().QueryRowContext(t.Context(), `SELECT instance_id FROM management_audit_settings`).Scan(&current); err != nil || len(current) != 32 {
			t.Fatalf("instance=%s err=%v", current, err)
		}
		if instance != "" && instance != current {
			t.Fatal("instance changed on restart")
		}
		instance = current
		if err = db.DB().QueryRowContext(t.Context(), `SELECT credential FROM management_users WHERE id='u'`).Scan(&proof); err != nil || proof != "private-record" {
			t.Fatal("identity changed", err)
		}
		if queryInt(t, db.DB(), `SELECT count(*) FROM management_security_events WHERE id=123`) != 1 {
			t.Fatal("history reset")
		}
		if err = db.Close(); err != nil {
			t.Fatal(err)
		}
	}
}
