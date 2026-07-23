package store_test

import (
	"context"
	json "encoding/json/v2"
	"errors"
	"path/filepath"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/auth"
	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	contractuser "github.com/Asutorufa/yuhaiin/pkg/contract/user"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
)

func TestUserStoreBasicRoundTripDoesNotExposeSecret(t *testing.T) {
	ctx := context.Background()
	db, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	store := plainstore.NewUserStore(db.DB())
	username, password := "alice", "secret"
	view, err := store.Create(ctx, contractuser.UserWrite{
		Name: "Alice", Enabled: true, Usage: contractuser.UsageBoth,
		Credential: contractuser.Credential{Type: contractuser.CredentialBasic, Basic: &contractuser.BasicCredential{Username: &username, Password: &password}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if view.Credential.Username != username || !view.Credential.HasSecret {
		t.Fatalf("view = %+v", view)
	}
	if view.Credential.Username == password {
		t.Fatal("password leaked in view")
	}

	stored, err := store.Get(ctx, view.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Credential.Basic == nil || *stored.Credential.Basic.Password != password {
		t.Fatalf("stored = %+v", stored)
	}

	center, err := auth.NewCenter(store)
	if err != nil {
		t.Fatal(err)
	}
	principal, err := center.AuthBasic(username, password)
	if err != nil || principal.UserID != view.ID {
		t.Fatalf("auth = %+v, err=%v", principal, err)
	}
	if _, err := center.AuthBasic(username, "wrong"); !errors.Is(err, auth.ErrNotFound) {
		t.Fatalf("wrong password error = %v", err)
	}

	if err := store.Delete(ctx, view.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(ctx, view.ID); !errors.Is(err, plainstore.ErrNotFound) {
		t.Fatalf("get deleted user error = %v", err)
	}
}

func TestUserStoreSupportsExplicitEmptyPassword(t *testing.T) {
	ctx := context.Background()
	db, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	store := plainstore.NewUserStore(db.DB())
	empty := ""
	view, err := store.Create(ctx, contractuser.UserWrite{
		Name: "Empty", Enabled: true, Usage: contractuser.UsageInbound,
		Credential: contractuser.Credential{Type: contractuser.CredentialBasic, Basic: &contractuser.BasicCredential{Password: &empty}},
	})
	if err != nil {
		t.Fatal(err)
	}
	center, err := auth.NewCenter(store)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := center.AuthPassword(""); err != nil || got.UserID != view.ID {
		t.Fatalf("empty password auth = %+v, err=%v", got, err)
	}
}

func TestUserStoreReportsAndProtectsOutboundReferences(t *testing.T) {
	ctx := context.Background()
	db, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := plainstore.NewUserStore(db.DB())
	password := "secret"
	view, err := store.Create(ctx, contractuser.UserWrite{
		Name: "Referenced", Enabled: true, Usage: contractuser.UsageOutbound,
		Credential: contractuser.Credential{Type: contractuser.CredentialBasic, Basic: &contractuser.BasicCredential{Password: &password}},
	})
	if err != nil {
		t.Fatal(err)
	}
	node := contractnode.Node{
		ID: "referencing-node", Name: "referencing-node", Group: "local", Origin: "manual", Enabled: true,
		Chain: []contractnode.Protocol{{Type: "http", HTTP: &contractnode.HTTP{UserID: view.ID}}},
	}
	data, err := json.Marshal(node)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB().ExecContext(ctx, `
		INSERT INTO nodes_v2(id, name, group_name, origin, enabled, chain_types_json, updated_at, data_json)
		VALUES (?, ?, ?, ?, 1, '["http"]', 1, ?)
	`, node.ID, node.Name, node.Group, node.Origin, string(data)); err != nil {
		t.Fatal(err)
	}
	views, err := store.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(views) != 1 || views[0].OutboundReferences != 1 {
		t.Fatalf("user views = %+v", views)
	}
	if err := store.Delete(ctx, view.ID); !errors.Is(err, plainstore.ErrUserReferenced) {
		t.Fatalf("delete referenced user error = %v", err)
	}
	if _, err := db.DB().ExecContext(ctx, `DELETE FROM nodes_v2 WHERE id = ?`, node.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.Delete(ctx, view.ID); err != nil {
		t.Fatalf("delete after reference removal = %v", err)
	}
}
