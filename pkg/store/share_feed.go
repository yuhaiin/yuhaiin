package store

import (
	"cmp"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"
	"uuid"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	contractsubscription "github.com/Asutorufa/yuhaiin/pkg/contract/subscription"
	"github.com/Asutorufa/yuhaiin/pkg/log"
)

const (
	maxShareFeedNameLength = 128
	maxShareFeedEntries    = 256
	maxShareFeedValue      = 256
	// The node list groups ungrouped nodes under this name.
	ungroupedNodeGroup = "manual"
)

// NewShareFeedToken returns 32 random bytes encoded for use in a URL path.
func NewShareFeedToken() string {
	token := make([]byte, 32)
	_, _ = rand.Read(token) // crypto/rand.Read never fails.
	return base64.RawURLEncoding.EncodeToString(token)
}

func (s *SubscriptionStore) ListShareFeeds(ctx context.Context) (contractsubscription.ShareFeedList, error) {
	if s == nil || s.db == nil {
		return contractsubscription.ShareFeedList{}, errors.New("subscription store database is nil")
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT f.id, f.data_json, COALESCE(a.last_access, 0), COALESCE(a.access_count, 0)
		FROM share_feeds f
		LEFT JOIN share_feed_access a ON a.id = f.id
	`)
	if err != nil {
		return contractsubscription.ShareFeedList{}, fmt.Errorf("query share feeds failed: %w", err)
	}
	defer rows.Close()
	out := contractsubscription.ShareFeedList{Items: []contractsubscription.ShareFeed{}}
	for rows.Next() {
		var id, dataJSON string
		var lastAccess, accessCount int64
		if err := rows.Scan(&id, &dataJSON, &lastAccess, &accessCount); err != nil {
			return contractsubscription.ShareFeedList{}, fmt.Errorf("scan share feed failed: %w", err)
		}
		feed, err := decodeShareFeed(id, dataJSON)
		if err != nil {
			log.Warn("skip invalid stored share feed", "id", id, "err", err)
			continue
		}
		feed.LastAccess, feed.AccessCount = lastAccess, accessCount
		out.Items = append(out.Items, feed)
	}
	if err := rows.Err(); err != nil {
		return contractsubscription.ShareFeedList{}, fmt.Errorf("iterate share feeds failed: %w", err)
	}
	slices.SortFunc(out.Items, func(a, b contractsubscription.ShareFeed) int {
		return cmp.Or(strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name)), strings.Compare(a.ID, b.ID))
	})
	return out, nil
}

func (s *SubscriptionStore) GetShareFeed(ctx context.Context, id string) (contractsubscription.ShareFeed, error) {
	if s == nil || s.db == nil {
		return contractsubscription.ShareFeed{}, errors.New("subscription store database is nil")
	}
	feed, err := getShareFeed(ctx, s.db, id)
	if err != nil {
		return feed, err
	}
	err = s.db.QueryRowContext(ctx, `SELECT last_access, access_count FROM share_feed_access WHERE id = ?`, id).Scan(&feed.LastAccess, &feed.AccessCount)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return feed, fmt.Errorf("query share feed access failed: %w", err)
	}
	return feed, nil
}

// CreateShareFeed stores a new feed with a server-generated ID and token. Any
// ID, token or statistics in the request are ignored.
func (s *SubscriptionStore) CreateShareFeed(ctx context.Context, request contractsubscription.ShareFeed) (contractsubscription.ShareFeed, error) {
	if s == nil || s.db == nil {
		return contractsubscription.ShareFeed{}, errors.New("subscription store database is nil")
	}
	feed, err := normalizeShareFeed(request)
	if err != nil {
		return contractsubscription.ShareFeed{}, err
	}
	now := time.Now().Unix()
	feed.ID = uuid.New().String()
	feed.Token = NewShareFeedToken()
	feed.CreatedAt, feed.UpdatedAt = now, now
	feed.LastAccess, feed.AccessCount = 0, 0
	if err := putShareFeed(ctx, s.db, feed, true); err != nil {
		return contractsubscription.ShareFeed{}, err
	}
	return feed, nil
}

// UpdateShareFeed changes the editable fields of an existing feed. The token,
// creation time and statistics always keep their stored values.
func (s *SubscriptionStore) UpdateShareFeed(ctx context.Context, request contractsubscription.ShareFeed) (contractsubscription.ShareFeed, error) {
	return s.modifyShareFeed(ctx, request.ID, func(feed *contractsubscription.ShareFeed) error {
		next, err := normalizeShareFeed(request)
		if err != nil {
			return err
		}
		feed.Name, feed.Enabled, feed.BaseURL, feed.Entries = next.Name, next.Enabled, next.BaseURL, next.Entries
		return nil
	})
}

// RotateShareFeedToken replaces the token; the previous link stops working.
func (s *SubscriptionStore) RotateShareFeedToken(ctx context.Context, id string) (contractsubscription.ShareFeed, error) {
	return s.modifyShareFeed(ctx, id, func(feed *contractsubscription.ShareFeed) error {
		feed.Token = NewShareFeedToken()
		return nil
	})
}

func (s *SubscriptionStore) modifyShareFeed(ctx context.Context, id string, change func(*contractsubscription.ShareFeed) error) (contractsubscription.ShareFeed, error) {
	if s == nil || s.db == nil {
		return contractsubscription.ShareFeed{}, errors.New("subscription store database is nil")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return contractsubscription.ShareFeed{}, err
	}
	defer func() { _ = tx.Rollback() }()
	feed, err := getShareFeed(ctx, tx, id)
	if err != nil {
		return contractsubscription.ShareFeed{}, err
	}
	if err := change(&feed); err != nil {
		return contractsubscription.ShareFeed{}, err
	}
	feed.UpdatedAt = max(time.Now().Unix(), feed.CreatedAt)
	if err := putShareFeed(ctx, tx, feed, false); err != nil {
		return contractsubscription.ShareFeed{}, err
	}
	if err := tx.Commit(); err != nil {
		return contractsubscription.ShareFeed{}, err
	}
	return s.GetShareFeed(ctx, id)
}

func (s *SubscriptionStore) DeleteShareFeed(ctx context.Context, id string) error {
	if s == nil || s.db == nil {
		return errors.New("subscription store database is nil")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `DELETE FROM share_feeds WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete share feed %q failed: %w", id, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: share feed %s not found", ErrNotFound, id)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM share_feed_access WHERE id = ?`, id); err != nil {
		return fmt.Errorf("delete share feed access %q failed: %w", id, err)
	}
	return tx.Commit()
}

// PreviewShareFeed reports what a feed with these entries would publish now.
func (s *SubscriptionStore) PreviewShareFeed(ctx context.Context, entries []contractsubscription.ShareFeedEntry) (contractsubscription.ShareFeedPreview, error) {
	if s == nil || s.db == nil {
		return contractsubscription.ShareFeedPreview{}, errors.New("subscription store database is nil")
	}
	entries, err := normalizeShareFeedEntries(entries)
	if err != nil {
		return contractsubscription.ShareFeedPreview{}, err
	}
	_, preview, err := expandShareFeed(ctx, s.db, entries)
	return preview, err
}

// ResolveShareFeed finds the enabled feed holding token and expands its
// entries. ok is false for an unknown token or a disabled feed.
func (s *SubscriptionStore) ResolveShareFeed(ctx context.Context, token string) (id string, document contractsubscription.ShareFeedDocument, ok bool, err error) {
	if s == nil || s.db == nil {
		return "", document, false, errors.New("subscription store database is nil")
	}
	if token == "" {
		return "", document, false, nil
	}
	want := sha256.Sum256([]byte(token))
	rows, err := s.db.QueryContext(ctx, `SELECT id, data_json FROM share_feeds`)
	if err != nil {
		return "", document, false, fmt.Errorf("query share feeds failed: %w", err)
	}
	var found *contractsubscription.ShareFeed
	for rows.Next() {
		var rowID, dataJSON string
		if err := rows.Scan(&rowID, &dataJSON); err != nil {
			_ = rows.Close()
			return "", document, false, fmt.Errorf("scan share feed failed: %w", err)
		}
		feed, err := decodeShareFeed(rowID, dataJSON)
		if err != nil || feed.Token == "" {
			continue
		}
		have := sha256.Sum256([]byte(feed.Token))
		// Compare every row in constant time so the scan does not reveal which
		// prefix matched.
		if subtle.ConstantTimeCompare(want[:], have[:]) == 1 && found == nil {
			found = &feed
		}
	}
	if err := rows.Close(); err != nil {
		return "", document, false, err
	}
	if found == nil || !found.Enabled {
		return "", document, false, nil
	}
	nodes, _, err := expandShareFeed(ctx, s.db, found.Entries)
	if err != nil {
		return "", document, false, err
	}
	return found.ID, contractsubscription.ShareFeedDocument{
		Version:     1,
		Name:        found.Name,
		GeneratedAt: time.Now().Unix(),
		Nodes:       nodes,
	}, true, nil
}

// RecordShareFeedAccess adds count fetches ending at the given time.
func (s *SubscriptionStore) RecordShareFeedAccess(ctx context.Context, id string, at, count int64) error {
	if s == nil || s.db == nil {
		return errors.New("subscription store database is nil")
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO share_feed_access(id, last_access, access_count)
		SELECT id, ?, ? FROM share_feeds WHERE id = ?
		ON CONFLICT(id) DO UPDATE SET
			last_access = max(last_access, excluded.last_access),
			access_count = access_count + excluded.access_count
	`, at, count, id)
	if err != nil {
		return fmt.Errorf("record share feed access failed: %w", err)
	}
	return nil
}

func expandShareFeed(ctx context.Context, queryer NodeQueryer, entries []contractsubscription.ShareFeedEntry) ([]contractnode.Node, contractsubscription.ShareFeedPreview, error) {
	preview := contractsubscription.ShareFeedPreview{
		Nodes:   []contractsubscription.ShareFeedPreviewNode{},
		Skipped: []contractsubscription.ShareFeedSkippedNode{},
		Missing: []contractsubscription.ShareFeedEntry{},
	}
	nodes := []contractnode.Node{}
	// seen records whether a node was already published (true) or skipped.
	seen := map[string]bool{}
	add := func(node contractnode.Node, from string) {
		if published, ok := seen[node.ID]; ok {
			if published {
				preview.Skipped = append(preview.Skipped, contractsubscription.ShareFeedSkippedNode{ID: node.ID, Name: node.Name, Reason: contractsubscription.ShareFeedSkipDuplicate})
			}
			return
		}
		reason := shareFeedSkipReason(node)
		seen[node.ID] = reason == ""
		if reason != "" {
			preview.Skipped = append(preview.Skipped, contractsubscription.ShareFeedSkippedNode{ID: node.ID, Name: node.Name, Reason: reason})
			return
		}
		nodes = append(nodes, node)
		preview.Nodes = append(preview.Nodes, contractsubscription.ShareFeedPreviewNode{ID: node.ID, Name: node.Name, Group: cmp.Or(node.Group, ungroupedNodeGroup), From: from})
	}
	for _, entry := range entries {
		switch entry.Kind {
		case contractsubscription.ShareFeedEntryNode:
			node, err := getNodeContract(ctx, queryer, entry.Value)
			if err != nil {
				if !errors.Is(err, ErrNotFound) {
					log.Warn("share feed skips unreadable node", "id", entry.Value, "err", err)
				}
				preview.Missing = append(preview.Missing, entry)
				continue
			}
			add(node, contractsubscription.ShareFeedEntryNode)
		case contractsubscription.ShareFeedEntryGroup:
			group, err := groupNodeContracts(ctx, queryer, entry.Value)
			if err != nil {
				return nil, preview, err
			}
			if len(group) == 0 {
				preview.Missing = append(preview.Missing, entry)
				continue
			}
			for _, node := range group {
				add(node, contractsubscription.ShareFeedEntryGroup+":"+entry.Value)
			}
		}
	}
	return nodes, preview, nil
}

// groupNodeContracts lists a group in the node list's order.
func groupNodeContracts(ctx context.Context, queryer NodeQueryer, group string) ([]contractnode.Node, error) {
	rows, err := queryer.QueryContext(ctx, `
		SELECT id, data_json FROM nodes_v2
		WHERE COALESCE(NULLIF(group_name, ''), ?) = ?
		ORDER BY name, id
	`, ungroupedNodeGroup, group)
	if err != nil {
		return nil, fmt.Errorf("query node group %q failed: %w", group, err)
	}
	defer rows.Close()
	var out []contractnode.Node
	for rows.Next() {
		var id, dataJSON string
		if err := rows.Scan(&id, &dataJSON); err != nil {
			return nil, fmt.Errorf("scan node failed: %w", err)
		}
		node, err := decodeNodeContract(dataJSON)
		if err != nil {
			log.Warn("share feed skips unreadable node", "id", id, "err", err)
			continue
		}
		out = append(out, node)
	}
	return out, rows.Err()
}

// shareFeedSkipReason reports why a node cannot be published. Set nodes name
// other local nodes and credential references name local credentials; neither
// exists on the subscriber.
func shareFeedSkipReason(node contractnode.Node) string {
	if !node.Enabled {
		return contractsubscription.ShareFeedSkipDisabled
	}
	reason := ""
	var visit func(contractnode.Protocol)
	visit = func(p contractnode.Protocol) {
		switch {
		case p.Type == "set" || p.Set != nil:
			reason = contractsubscription.ShareFeedSkipLocalReferences
		case p.CredentialRef != "" && reason == "":
			reason = contractsubscription.ShareFeedSkipLocalCredential
		}
		if split := p.NetworkSplit; split != nil {
			for _, child := range []*contractnode.Protocol{split.TCP, split.UDP} {
				if child != nil {
					visit(*child)
				}
			}
		}
	}
	for _, protocol := range node.Chain {
		visit(protocol)
	}
	return reason
}

func normalizeShareFeed(feed contractsubscription.ShareFeed) (contractsubscription.ShareFeed, error) {
	feed.Name = strings.TrimSpace(feed.Name)
	if feed.Name == "" {
		return feed, errors.New("share feed name is empty")
	}
	if len(feed.Name) > maxShareFeedNameLength {
		return feed, errors.New("share feed name is too long")
	}
	baseURL, err := normalizeShareFeedBaseURL(feed.BaseURL)
	if err != nil {
		return feed, err
	}
	feed.BaseURL = baseURL
	feed.Entries, err = normalizeShareFeedEntries(feed.Entries)
	return feed, err
}

// normalizeShareFeedBaseURL accepts an empty value or an http(s) origin with an
// optional path prefix for a reverse proxy.
func normalizeShareFeedBaseURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("share feed base URL must be an http or https URL without credentials, query or fragment")
	}
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawPath = ""
	return u.String(), nil
}

func normalizeShareFeedEntries(entries []contractsubscription.ShareFeedEntry) ([]contractsubscription.ShareFeedEntry, error) {
	if len(entries) > maxShareFeedEntries {
		return nil, fmt.Errorf("share feed has more than %d entries", maxShareFeedEntries)
	}
	out := make([]contractsubscription.ShareFeedEntry, 0, len(entries))
	for _, entry := range entries {
		entry.Kind = strings.TrimSpace(entry.Kind)
		entry.Value = strings.TrimSpace(entry.Value)
		if entry.Kind != contractsubscription.ShareFeedEntryGroup && entry.Kind != contractsubscription.ShareFeedEntryNode {
			return nil, fmt.Errorf("unknown share feed entry kind %q", entry.Kind)
		}
		if entry.Value == "" || len(entry.Value) > maxShareFeedValue {
			return nil, errors.New("share feed entry value is empty or too long")
		}
		if slices.Contains(out, entry) {
			continue
		}
		out = append(out, entry)
	}
	return out, nil
}

func getShareFeed(ctx context.Context, queryer NodeQueryer, id string) (contractsubscription.ShareFeed, error) {
	var dataJSON string
	err := queryer.QueryRowContext(ctx, `SELECT data_json FROM share_feeds WHERE id = ?`, id).Scan(&dataJSON)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return contractsubscription.ShareFeed{}, fmt.Errorf("%w: share feed %s not found", ErrNotFound, id)
	case err != nil:
		return contractsubscription.ShareFeed{}, fmt.Errorf("query share feed %q failed: %w", id, err)
	}
	return decodeShareFeed(id, dataJSON)
}

func putShareFeed(ctx context.Context, execer NodeExecer, feed contractsubscription.ShareFeed, create bool) error {
	// Statistics live in share_feed_access, not in the configuration document.
	feed.LastAccess, feed.AccessCount = 0, 0
	dataJSON, err := json.Marshal(feed)
	if err != nil {
		return fmt.Errorf("encode share feed %q failed: %w", feed.ID, err)
	}
	statement := `UPDATE share_feeds SET updated_at = ?, data_json = ? WHERE id = ?`
	args := []any{feed.UpdatedAt, string(dataJSON), feed.ID}
	if create {
		statement = `INSERT INTO share_feeds(updated_at, data_json, id) VALUES (?, ?, ?)`
	}
	res, err := execer.ExecContext(ctx, statement, args...)
	if err != nil {
		return fmt.Errorf("save share feed %q failed: %w", feed.ID, err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return fmt.Errorf("%w: share feed %s not found", ErrNotFound, feed.ID)
	}
	return nil
}

func decodeShareFeed(id, dataJSON string) (contractsubscription.ShareFeed, error) {
	var feed contractsubscription.ShareFeed
	if err := json.Unmarshal([]byte(dataJSON), &feed); err != nil {
		return contractsubscription.ShareFeed{}, fmt.Errorf("decode share feed %q failed: %w", id, err)
	}
	feed.ID = id
	if strings.TrimSpace(feed.Name) == "" {
		return contractsubscription.ShareFeed{}, fmt.Errorf("stored share feed %q has no name", id)
	}
	if feed.Entries == nil {
		feed.Entries = []contractsubscription.ShareFeedEntry{}
	}
	feed.LastAccess, feed.AccessCount = 0, 0
	return feed, nil
}
