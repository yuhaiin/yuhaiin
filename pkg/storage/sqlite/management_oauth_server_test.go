package sqlite

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
)

func TestManagementOAuthServerMigrationKeepsCredentials(t *testing.T) {
	path := filepath.Join(t.TempDir(), "management.db")
	prior, err := knownMigrations("management")
	if err != nil {
		t.Fatal(err)
	}
	if prior[len(prior)-1].Name != managementOAuthServerMigration.Name {
		t.Fatal("the OAuth migration must be the newest management migration for this test")
	}
	prior = prior[:len(prior)-1]
	old, err := open(t.Context(), path, "management", func(ctx context.Context, db *sql.DB) error {
		if err := bootstrapBase(ctx, db); err != nil {
			return err
		}
		for _, migration := range prior {
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
		`INSERT INTO management_users(id,login,role,client_salt,created_at,updated_at) VALUES('u','legacy','admin',x'00',1,1)`,
		`INSERT INTO management_credentials(id,user_id,kind,verifier,prefix,scopes,generation,created_at,expires_at,revoked,user_agent,remote_addr,last_seen,auth_method,name,note)
			VALUES('t','u','token',x'01','yu_legacy00','["nodes:read"]',1,1,0,0,'','',0,'token','label','note'),
			('s','u','session',x'02','yu_session0','null',1,1,99,0,'agent','127.0.0.1',5,'passkey','','')`,
	} {
		if _, err := old.DB().ExecContext(t.Context(), statement); err != nil {
			t.Fatal(err)
		}
	}
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	for range 2 { // idempotent: the second open applies nothing
		upgraded, err := OpenManagement(t.Context(), path)
		if err != nil {
			t.Fatal(err)
		}
		db := upgraded.DB()
		var name, note, agent, method string
		var seen int64
		if err := db.QueryRowContext(t.Context(), `SELECT name,note FROM management_credentials WHERE id='t' AND kind='token' AND scopes='["nodes:read"]'`).Scan(&name, &note); err != nil || name != "label" || note != "note" {
			t.Fatal("token not preserved", err)
		}
		if err := db.QueryRowContext(t.Context(), `SELECT user_agent,auth_method,last_seen FROM management_credentials WHERE id='s' AND kind='session' AND expires_at=99`).Scan(&agent, &method, &seen); err != nil || agent != "agent" || method != "passkey" || seen != 5 {
			t.Fatal("session not preserved", err)
		}
		if queryInt(t, db, `SELECT count(*) FROM migrate WHERE name='management_oauth_server'`) != 1 || queryInt(t, db, `SELECT enabled FROM management_oauth_server WHERE id=1`) != 0 {
			t.Fatal("migration state")
		}
		// OAuth credentials must belong to a grant; legacy ones must not.
		if _, err := db.ExecContext(t.Context(), `INSERT INTO management_credentials(id,user_id,kind,verifier,prefix,scopes,generation,created_at) VALUES('a','u','oauth_access',x'03','yuat_x','[]',1,1)`); err == nil {
			t.Fatal("OAuth credential without a grant accepted")
		}
		if _, err := db.ExecContext(t.Context(), `INSERT INTO management_credentials(id,user_id,kind,verifier,prefix,scopes,generation,created_at) VALUES('x','u','other',x'04','x','[]',1,1)`); err == nil {
			t.Fatal("unknown credential kind accepted")
		}
		if _, err := db.ExecContext(t.Context(), `INSERT INTO management_oauth_clients(id,name,client_type,registration,redirect_uris,token_endpoint_auth_method,secret_hash,grant_types,scopes,resources,created_at,updated_at) VALUES('c','c','public','manual','[]','none',x'01','[]','[]','[]',1,1)`); err == nil {
			t.Fatal("public client with a secret accepted")
		}
		if err := upgraded.Close(); err != nil {
			t.Fatal(err)
		}
	}
}
