package sqlite

import (
	"bytes"
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
)

func TestManagementDatabasePrivateSeparateAndIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "management.db")
	db, err := OpenManagement(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(t.Context(), path); err == nil {
		t.Fatal("configuration store accepted a live management database")
	}
	if _, err := db.DB().ExecContext(t.Context(), `INSERT INTO management_users(id,login,role,client_salt,credential,created_at,updated_at) VALUES('admin','admin','admin',randomblob(16),randomblob(32),1,1)`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = OpenManagement(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if queryInt(t, db.DB(), `SELECT count(*) FROM management_users`) != 1 {
		t.Fatal("migration replaced identities")
	}
	if queryInt(t, db.DB(), `SELECT count(*) FROM migrate`) != 6 {
		t.Fatal("migration applied more than once")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("private database mode: %v", info.Mode())
	}
	config, err := Open(t.Context(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer config.Close()
	if _, err := OpenManagement(t.Context(), config.Path()); err == nil {
		t.Fatal("management store accepted a live state database")
	}
	backup, err := ExportConfig(t.Context(), config.DB())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(backup, []byte("management_")) {
		t.Fatal("ordinary configuration export includes management identities")
	}
	if schemaObjectExists(t, config.DB(), "management_users") {
		t.Fatal("authentication table created in state database")
	}
}

func TestManagementSSTPMigrationPreservesExistingCredentialsAndSnapshots(t *testing.T) {
	path := filepath.Join(t.TempDir(), "management.db")
	old, err := open(t.Context(), path, "management", func(ctx context.Context, db *sql.DB) error {
		if err := bootstrapBase(ctx, db); err != nil {
			return err
		}
		for _, migration := range []Migration{managementAuthMigration, managementInitializationMigration, proxyCredentialsMigration, managementOAuthMigration, managementAuditMigration} {
			if err := applyMigration(ctx, db, migration); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := old.DB().ExecContext(t.Context(), `INSERT INTO management_users(id,login,role,client_salt,credential,created_at,updated_at) VALUES('owner','owner','admin',randomblob(16),randomblob(32),1,1);
		INSERT INTO proxy_credentials(id,user_id,name,verifier,wire_verifier,generation,inbounds,protocols,created_at) VALUES('credential','owner','legacy',x'0102',x'0304',1,'[]','["sstp"]',1)`); err != nil {
		t.Fatal(err)
	}
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	upgraded, err := OpenManagement(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	var verifier, wire, ntHash []byte
	if err := upgraded.DB().QueryRowContext(t.Context(), `SELECT verifier, wire_verifier, sstp_nt_hash FROM proxy_credentials WHERE id='credential'`).Scan(&verifier, &wire, &ntHash); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(verifier, []byte{1, 2}) || !bytes.Equal(wire, []byte{3, 4}) || ntHash != nil {
		t.Fatal("migration changed existing verifiers or fabricated an SSTP hash")
	}
	if err := upgraded.Close(); err != nil {
		t.Fatal(err)
	}
	if catalog, err := InspectStoreCatalog(t.Context(), path, "management"); err != nil || len(catalog) != 6 || catalog[5].Name != "sstp_proxy_verifiers" {
		t.Fatalf("upgraded management catalog = %v: %v", catalog, err)
	}
	snapshot := filepath.Join(t.TempDir(), "snapshot.db")
	version, err := SnapshotRecoveryDatabase(t.Context(), path, snapshot, "management", 1<<30)
	if err != nil || version != 6 {
		t.Fatalf("snapshot of upgraded management store: version=%d err=%v", version, err)
	}
	reopened, err := OpenManagement(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestManagementInitializationMigration(t *testing.T) {
	for _, state := range []string{"empty", "pending", "enrolled", "reset"} {
		t.Run(state, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "management.db")
			old, err := open(t.Context(), path, "management", func(ctx context.Context, db *sql.DB) error {
				if err := bootstrapBase(ctx, db); err != nil {
					return err
				}
				return applyMigration(ctx, db, managementAuthMigration)
			})
			if err != nil {
				t.Fatal(err)
			}
			if state != "empty" {
				var verifier any
				if state == "enrolled" {
					verifier = []byte("old-verifier")
				}
				if _, err := old.DB().ExecContext(t.Context(), `INSERT INTO management_users(id,login,role,client_salt,credential,created_at,updated_at) VALUES('owner','owner','admin',randomblob(16),?,1,1)`, verifier); err != nil {
					t.Fatal(err)
				}
			}
			if state == "reset" {
				if _, err := old.DB().ExecContext(t.Context(), `INSERT INTO management_security_events(occurred_at,event,actor_id,subject_id) VALUES(1,'user.enrolled','owner','owner'),(2,'user.credentials_reset','owner','owner')`); err != nil {
					t.Fatal(err)
				}
			}
			if err := old.Close(); err != nil {
				t.Fatal(err)
			}
			upgraded, err := OpenManagement(t.Context(), path)
			if err != nil {
				t.Fatal(err)
			}
			defer upgraded.Close()
			var want int64
			if state == "enrolled" || state == "reset" {
				want = 1
			}
			if got := queryInt(t, upgraded.DB(), `SELECT completed FROM management_initialization`); got != want {
				t.Fatalf("completion after upgrade=%d want=%d", got, want)
			}
			// The completion trigger also covers manual CLI enrollment after upgrade.
			if state == "pending" {
				if _, err := upgraded.DB().ExecContext(t.Context(), `UPDATE management_users SET credential=randomblob(32) WHERE id='owner'`); err != nil {
					t.Fatal(err)
				}
				if queryInt(t, upgraded.DB(), `SELECT completed FROM management_initialization`) != 1 {
					t.Fatal("manual enrollment did not close setup")
				}
			}
		})
	}
}

func TestOAuthSessionMigrationPreservesExistingCredentials(t *testing.T) {
	path := filepath.Join(t.TempDir(), "management.db")
	old, err := open(t.Context(), path, "management", func(ctx context.Context, db *sql.DB) error {
		if err := bootstrapBase(ctx, db); err != nil {
			return err
		}
		for _, migration := range []Migration{managementAuthMigration, managementInitializationMigration, proxyCredentialsMigration} {
			if err := applyMigration(ctx, db, migration); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := old.DB().ExecContext(t.Context(), `INSERT INTO management_users(id,login,role,client_salt,credential,created_at,updated_at) VALUES('owner','owner','admin',randomblob(16),randomblob(32),1,1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := old.DB().ExecContext(t.Context(), `INSERT INTO management_credentials(id,user_id,kind,verifier,prefix,scopes,generation,created_at,expires_at) VALUES('old-session','owner','session',x'1234','prefix','null',1,1,9999999999)`); err != nil {
		t.Fatal(err)
	}
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := OpenManagement(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var verifier []byte
	var method, agent, address string
	var seen int64
	if err := db.DB().QueryRowContext(t.Context(), `SELECT verifier,auth_method,user_agent,remote_addr,last_seen FROM management_credentials WHERE id='old-session'`).Scan(&verifier, &method, &agent, &address, &seen); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(verifier, []byte{0x12, 0x34}) || method != "password" || agent != "" || address != "" || seen != 0 {
		t.Fatal("migration changed existing credential or invented device metadata")
	}
}
