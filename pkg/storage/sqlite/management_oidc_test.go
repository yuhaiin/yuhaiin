package sqlite

import (
	"context"
	"database/sql"
	"path/filepath"
	"slices"
	"testing"
)

func TestOIDCMigrationPreservesLegacyBindingsAndRollsBackOnInterruption(t *testing.T) {
	path := filepath.Join(t.TempDir(), "management.db")
	old, err := open(t.Context(), path, "management", func(ctx context.Context, db *sql.DB) error {
		if err := bootstrapBase(ctx, db); err != nil {
			return err
		}
		for _, migration := range []Migration{managementAuthMigration, managementInitializationMigration, proxyCredentialsMigration, managementOAuthMigration, managementAuditMigration, trafficGroupsMigration, trafficAccessMigration, resourceGovernanceMigration, managementRolesMigration} {
			if err := applyMigration(ctx, db, migration); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		`INSERT INTO management_users(id,login,role,disabled,created_at,updated_at,generation,client_salt) VALUES('u','admin','admin',0,1,1,1,zeroblob(16))`,
		`INSERT INTO management_oauth_providers(provider,client_id,client_secret,redirect_url) VALUES('github','legacy-client','private-client-secret','https://controller.test/api/v2/auth/oauth/github/callback')`,
		`INSERT INTO management_oauth_links(provider,subject,user_id,display_name,created_at) VALUES('github','legacy-subject','u','Legacy name',123)`,
	} {
		if _, err := old.DB().ExecContext(t.Context(), statement); err != nil {
			t.Fatal(err)
		}
	}
	broken := managementOIDCMigration
	broken.Statements = append(slices.Clone(broken.Statements), "INTERRUPTED MIGRATION")
	if err := applyMigration(t.Context(), old.DB(), broken); err == nil {
		t.Fatal("broken migration committed")
	}
	if queryInt(t, old.DB(), `SELECT count(*) FROM management_oauth_links WHERE subject='legacy-subject'`) != 1 || queryInt(t, old.DB(), `SELECT count(*) FROM migrate`) != 9 {
		t.Fatal("interrupted migration lost legacy state")
	}
	if _, err := old.DB().ExecContext(t.Context(), `SELECT issuer FROM management_oauth_providers`); err == nil {
		t.Fatal("partial OIDC schema survived interruption")
	}
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		upgraded, err := OpenManagement(t.Context(), path)
		if err != nil {
			t.Fatal(err)
		}
		var secret, issuer string
		var revision int
		if err := upgraded.DB().QueryRowContext(t.Context(), `SELECT client_secret,issuer,revision FROM management_oauth_providers WHERE provider='github'`).Scan(&secret, &issuer, &revision); err != nil || secret != "private-client-secret" || issuer != "" || revision != 1 {
			t.Fatal("legacy provider changed during migration", err)
		}
		if queryInt(t, upgraded.DB(), `SELECT count(*) FROM management_oauth_links WHERE user_id='u' AND subject='legacy-subject' AND issuer='https://github.com'`) != 1 || queryInt(t, upgraded.DB(), `SELECT count(*) FROM migrate`) != 10 {
			t.Fatal("legacy binding missing or migration repeated")
		}
		if err := upgraded.Close(); err != nil {
			t.Fatal(err)
		}
	}
}
