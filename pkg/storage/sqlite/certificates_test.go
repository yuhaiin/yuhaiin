package sqlite

import (
	"database/sql"
	"path/filepath"
	"testing"
)

func TestManagedCertificatesUpgradeExisting23(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	db, err := sql.Open(driverName, path)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	if err := configure(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	if err := bootstrapBase(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	for _, migration := range migrations[:23] {
		if err := applyMigration(t.Context(), db, migration); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.ExecContext(t.Context(), `INSERT INTO gateway_ca(id,revision,certificate_pem,private_key_pem) VALUES(1,1,'existing MITM CA','existing MITM key')`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	upgraded, err := Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer upgraded.Close()
	for _, table := range []string{"managed_certificates", "managed_certificate_material", "certificate_dns_providers", "certificate_acme_accounts", "certificate_references", "certificate_dns_cleanup"} {
		if !schemaObjectExists(t, upgraded.DB(), table) {
			t.Fatal("missing certificate table", table)
		}
	}
	var oldKey string
	if err := upgraded.DB().QueryRowContext(t.Context(), `SELECT private_key_pem FROM gateway_ca WHERE id=1`).Scan(&oldKey); err != nil || oldKey != "existing MITM key" {
		t.Fatal("site certificate migration modified MITM CA", err)
	}
	if version := queryString(t, upgraded.DB(), `SELECT value FROM metadata WHERE key='schema_version'`); version != "25" {
		t.Fatal(version)
	}
}
