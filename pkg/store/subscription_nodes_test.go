package store

import (
	"context"
	"path/filepath"
	"testing"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	contractsubscription "github.com/Asutorufa/yuhaiin/pkg/contract/subscription"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
)

func TestReplaceRemoteMigratesCredentialsAndLinksSubscription(t *testing.T) {
	ctx := context.Background()
	sqliteStore, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer sqliteStore.Close()

	subscriptions := NewSubscriptionStore(sqliteStore.DB())
	if err := subscriptions.SaveLinks(ctx, []contractsubscription.Link{{Name: "remote", URL: "https://example.com/sub"}}, 0); err != nil {
		t.Fatal(err)
	}

	nodes := NewNodeStore(sqliteStore.DB())
	node := contractnode.Node{
		ID: "node-1", Name: "Remote node", Enabled: true,
		Chain: []contractnode.Protocol{{Type: "trojan", Trojan: &contractnode.Trojan{Password: "remote-secret", Peer: "example.com"}}},
	}
	if err := nodes.ReplaceRemote(ctx, "remote", []contractnode.Node{node}, 0); err != nil {
		t.Fatal(err)
	}

	stored, err := nodes.Get(ctx, node.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Chain[0].Trojan.UserID == "" || stored.Chain[0].Trojan.Password != "" { //nolint:staticcheck // assert migrated storage clears the legacy credential field.
		t.Fatalf("stored remote credentials = %+v", stored.Chain[0].Trojan)
	}
	var userCount int
	if err := sqliteStore.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM subscription_users_v2 WHERE subscription_name = 'remote'`).Scan(&userCount); err != nil {
		t.Fatal(err)
	}
	if userCount != 1 {
		t.Fatalf("subscription user count = %d, want 1", userCount)
	}

	impact, err := subscriptions.DeleteImpact(ctx, []string{"remote"})
	if err != nil {
		t.Fatal(err)
	}
	if impact.Nodes != 1 || impact.Users != 1 {
		t.Fatalf("delete impact = %+v, want one node and one user", impact)
	}
	if err := subscriptions.DeleteLinksWithOptions(ctx, contractsubscription.DeleteLinksRequest{
		Names: []string{"remote"}, DeleteNodes: true, DeleteUsers: true,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := nodes.Get(ctx, node.ID); err == nil {
		t.Fatal("remote node was not deleted")
	}
	if err := sqliteStore.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM users_v2`).Scan(&userCount); err != nil {
		t.Fatal(err)
	}
	if userCount != 0 {
		t.Fatalf("users after subscription deletion = %d, want 0", userCount)
	}
}
