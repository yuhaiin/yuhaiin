package sqlite

import (
	"context"
	"database/sql"
	"path/filepath"
	"slices"
	"testing"
)

func TestConfigurationChangeMigrationsAreAtomicAndRestartable(t *testing.T) {
	management := []Migration{managementAuthMigration, managementInitializationMigration, proxyCredentialsMigration, managementOAuthMigration, managementAuditMigration, trafficGroupsMigration, trafficAccessMigration, resourceGovernanceMigration, managementRolesMigration, managementOIDCMigration, managementSecurityAuditMigration}
	for _, test := range []struct {
		name   string
		prior  []Migration
		next   Migration
		reopen func(context.Context, string) (*Store, error)
	}{
		{"management", management, managementConfigurationChangesMigration, OpenManagement},
		{"configuration", migrations[:len(migrations)-1], configurationChangesMigration, Open},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state.db")
			old, err := open(t.Context(), path, test.name, func(ctx context.Context, db *sql.DB) error {
				if err := bootstrapBase(ctx, db); err != nil {
					return err
				}
				for _, migration := range test.prior {
					if err := applyMigration(ctx, db, migration); err != nil {
						return err
					}
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			broken := test.next
			broken.Statements = append(slices.Clone(broken.Statements), "INTERRUPTED MIGRATION")
			if err = applyMigration(t.Context(), old.DB(), broken); err == nil {
				t.Fatal("interrupted migration succeeded")
			}
			if schemaObjectExists(t, old.DB(), "configuration_changes") || queryInt(t, old.DB(), `SELECT count(*) FROM migrate`) != int64(test.next.Version-1) {
				t.Fatal("partial migration survived")
			}
			if test.name == "management" && schemaObjectExists(t, old.DB(), "management_oauth_revisions") {
				t.Fatal("partial provider clock survived")
			}
			if err = old.Close(); err != nil {
				t.Fatal(err)
			}
			for range 2 {
				upgraded, err := test.reopen(t.Context(), path)
				if err != nil {
					t.Fatal(err)
				}
				if !schemaObjectExists(t, upgraded.DB(), "configuration_changes") || queryInt(t, upgraded.DB(), `SELECT count(*) FROM migrate`) != int64(test.next.Version) {
					t.Fatal("migration missing or repeated")
				}
				if test.name == "configuration" && schemaObjectExists(t, upgraded.DB(), "management_users") {
					t.Fatal("identity database leaked into configuration")
				}
				if err = upgraded.Close(); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
