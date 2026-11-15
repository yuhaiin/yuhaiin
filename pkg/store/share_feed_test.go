package store

import (
	"errors"
	"path/filepath"
	"slices"
	"testing"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	contractsubscription "github.com/Asutorufa/yuhaiin/pkg/contract/subscription"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
)

func openShareFeedStore(t *testing.T) (*SubscriptionStore, *NodeStore) {
	t.Helper()
	db, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return NewSubscriptionStore(db.DB()), NewNodeStore(db.DB())
}

func saveShareFeedNode(t *testing.T, nodes *NodeStore, id, name, group string, enabled bool, chain ...contractnode.Protocol) {
	t.Helper()
	if len(chain) == 0 {
		chain = []contractnode.Protocol{{Type: "direct", Direct: &contractnode.Direct{}}}
	}
	node := contractnode.Node{ID: id, Name: name, Group: group, Origin: "manual", Enabled: enabled, Chain: chain}
	if err := nodes.Save(t.Context(), node, 0); err != nil {
		t.Fatalf("save node %s: %v", id, err)
	}
}

func groupEntry(name string) contractsubscription.ShareFeedEntry {
	return contractsubscription.ShareFeedEntry{Kind: contractsubscription.ShareFeedEntryGroup, Value: name}
}

func nodeEntry(id string) contractsubscription.ShareFeedEntry {
	return contractsubscription.ShareFeedEntry{Kind: contractsubscription.ShareFeedEntryNode, Value: id}
}

func TestShareFeedLifecycle(t *testing.T) {
	ctx := t.Context()
	feeds, nodes := openShareFeedStore(t)
	saveShareFeedNode(t, nodes, "a", "alpha", "g", true)

	created, err := feeds.CreateShareFeed(ctx, contractsubscription.ShareFeed{
		ID: "client-id", Token: "client-token", Name: " friends ", Enabled: true,
		BaseURL: "https://example.com:8443/", Entries: []contractsubscription.ShareFeedEntry{nodeEntry("a"), nodeEntry("a")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if created.ID == "client-id" || created.Token == "client-token" || len(created.Token) != 43 {
		t.Fatalf("server must generate the id and token: %+v", created)
	}
	if created.Name != "friends" || created.BaseURL != "https://example.com:8443" || len(created.Entries) != 1 {
		t.Fatalf("create did not normalize the feed: %+v", created)
	}

	updated, err := feeds.UpdateShareFeed(ctx, contractsubscription.ShareFeed{ID: created.ID, Token: "attacker", Name: "renamed", Enabled: false, Entries: []contractsubscription.ShareFeedEntry{groupEntry("g")}})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Token != created.Token || updated.Name != "renamed" || updated.Enabled || updated.CreatedAt != created.CreatedAt {
		t.Fatalf("update changed the token or lost fields: %+v", updated)
	}

	rotated, err := feeds.RotateShareFeedToken(ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if rotated.Token == created.Token || rotated.Name != "renamed" {
		t.Fatalf("rotate = %+v", rotated)
	}

	if err := feeds.RecordShareFeedAccess(ctx, created.ID, 100, 2); err != nil {
		t.Fatal(err)
	}
	if err := feeds.RecordShareFeedAccess(ctx, created.ID, 50, 1); err != nil {
		t.Fatal(err)
	}
	list, err := feeds.ListShareFeeds(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Items) != 1 || list.Items[0].LastAccess != 100 || list.Items[0].AccessCount != 3 {
		t.Fatalf("list = %+v", list.Items)
	}

	if err := feeds.DeleteShareFeed(ctx, created.ID); err != nil {
		t.Fatal(err)
	}
	if err := feeds.DeleteShareFeed(ctx, created.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second delete error = %v", err)
	}
	if _, err := feeds.UpdateShareFeed(ctx, contractsubscription.ShareFeed{ID: created.ID, Name: "x"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("update of deleted feed error = %v", err)
	}
	// Statistics of a deleted feed are not recorded.
	if err := feeds.RecordShareFeedAccess(ctx, created.ID, 1, 1); err != nil {
		t.Fatal(err)
	}
	var orphaned int
	if err := feeds.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM share_feed_access`).Scan(&orphaned); err != nil || orphaned != 0 {
		t.Fatalf("orphaned access rows = %d, %v", orphaned, err)
	}
}

func TestShareFeedValidation(t *testing.T) {
	feeds, _ := openShareFeedStore(t)
	for _, feed := range []contractsubscription.ShareFeed{
		{Name: ""},
		{Name: "x", BaseURL: "ftp://example.com"},
		{Name: "x", BaseURL: "https://user:pass@example.com"},
		{Name: "x", BaseURL: "https://example.com/?a=b"},
		{Name: "x", Entries: []contractsubscription.ShareFeedEntry{{Kind: "selector", Value: "a"}}},
		{Name: "x", Entries: []contractsubscription.ShareFeedEntry{{Kind: "node", Value: " "}}},
	} {
		if _, err := feeds.CreateShareFeed(t.Context(), feed); err == nil {
			t.Fatalf("accepted invalid feed %+v", feed)
		}
	}
}

func TestShareFeedExpansion(t *testing.T) {
	ctx := t.Context()
	feeds, nodes := openShareFeedStore(t)
	saveShareFeedNode(t, nodes, "a2", "beta", "aws", true)
	saveShareFeedNode(t, nodes, "a1", "alpha", "aws", true)
	saveShareFeedNode(t, nodes, "off", "disabled", "aws", false)
	saveShareFeedNode(t, nodes, "set", "balanced", "aws", true, contractnode.Protocol{Type: "set", Set: &contractnode.Set{Nodes: []string{"a1"}}})
	saveShareFeedNode(t, nodes, "split", "split", "aws", true, contractnode.Protocol{Type: "network_split", NetworkSplit: &contractnode.NetworkSplit{
		TCP: &contractnode.Protocol{Type: "direct", Direct: &contractnode.Direct{}},
		UDP: &contractnode.Protocol{Type: "set", Set: &contractnode.Set{Nodes: []string{"a1"}}},
	}})
	saveShareFeedNode(t, nodes, "m", "manual-node", "", true)

	preview, err := feeds.PreviewShareFeed(ctx, []contractsubscription.ShareFeedEntry{
		nodeEntry("a2"), groupEntry("aws"), groupEntry("manual"), nodeEntry("gone"), groupEntry("gone"),
	})
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, node := range preview.Nodes {
		ids = append(ids, node.ID+"@"+node.From)
	}
	if want := []string{"a2@node", "a1@group:aws", "m@group:manual"}; !slices.Equal(ids, want) {
		t.Fatalf("published = %v, want %v", ids, want)
	}
	skipped := map[string]string{}
	for _, node := range preview.Skipped {
		skipped[node.ID] = node.Reason
	}
	want := map[string]string{
		"a2":    contractsubscription.ShareFeedSkipDuplicate,
		"off":   contractsubscription.ShareFeedSkipDisabled,
		"set":   contractsubscription.ShareFeedSkipLocalReferences,
		"split": contractsubscription.ShareFeedSkipLocalReferences,
	}
	if len(skipped) != len(want) {
		t.Fatalf("skipped = %v, want %v", skipped, want)
	}
	for id, reason := range want {
		if skipped[id] != reason {
			t.Fatalf("skipped = %v, want %v", skipped, want)
		}
	}
	if !slices.Equal(preview.Missing, []contractsubscription.ShareFeedEntry{nodeEntry("gone"), groupEntry("gone")}) {
		t.Fatalf("missing = %+v", preview.Missing)
	}
}

func TestShareFeedSkipsLocalCredentials(t *testing.T) {
	node := contractnode.Node{Enabled: true, Chain: []contractnode.Protocol{{Type: "trojan", CredentialRef: "cred", Trojan: &contractnode.Trojan{}}}}
	if reason := shareFeedSkipReason(node); reason != contractsubscription.ShareFeedSkipLocalCredential {
		t.Fatalf("reason = %q", reason)
	}
}

func TestResolveShareFeed(t *testing.T) {
	ctx := t.Context()
	feeds, nodes := openShareFeedStore(t)
	saveShareFeedNode(t, nodes, "a", "alpha", "g", true)
	feed, err := feeds.CreateShareFeed(ctx, contractsubscription.ShareFeed{Name: "f", Enabled: true, Entries: []contractsubscription.ShareFeedEntry{groupEntry("g")}})
	if err != nil {
		t.Fatal(err)
	}
	// A feed restored from a shared export has no token and is unreachable.
	if _, err := feeds.db.ExecContext(ctx, `INSERT INTO share_feeds(id,updated_at,data_json) VALUES('empty',1,'{"name":"e","enabled":true,"token":""}')`); err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{"", "wrong", feed.Token + "x"} {
		if _, _, ok, err := feeds.ResolveShareFeed(ctx, token); err != nil || ok {
			t.Fatalf("token %q resolved: ok=%v err=%v", token, ok, err)
		}
	}
	id, document, ok, err := feeds.ResolveShareFeed(ctx, feed.Token)
	if err != nil || !ok || id != feed.ID {
		t.Fatalf("resolve = %q %v %v", id, ok, err)
	}
	if document.Version != 1 || document.Name != "f" || len(document.Nodes) != 1 || document.Nodes[0].ID != "a" || len(document.Nodes[0].Chain) != 1 {
		t.Fatalf("document = %+v", document)
	}

	feed.Enabled = false
	if _, err := feeds.UpdateShareFeed(ctx, feed); err != nil {
		t.Fatal(err)
	}
	if _, _, ok, err := feeds.ResolveShareFeed(ctx, feed.Token); err != nil || ok {
		t.Fatalf("disabled feed resolved: ok=%v err=%v", ok, err)
	}
}
