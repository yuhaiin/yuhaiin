package store

import (
	"context"
	"crypto/subtle"
	"database/sql"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"strings"
	"time"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	contractsubscription "github.com/Asutorufa/yuhaiin/pkg/contract/subscription"
	contractuser "github.com/Asutorufa/yuhaiin/pkg/contract/user"
)

type SubscriptionStore struct {
	db *sql.DB
}

func NewSubscriptionStore(db *sql.DB) *SubscriptionStore {
	return &SubscriptionStore{db: db}
}

func (s *SubscriptionStore) ListLinks(ctx context.Context) (contractsubscription.LinkList, error) {
	if s == nil || s.db == nil {
		return contractsubscription.LinkList{}, errors.New("subscription store database is nil")
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT name, data_json
		FROM subscriptions
		ORDER BY name
	`)
	if err != nil {
		return contractsubscription.LinkList{}, fmt.Errorf("query subscription contracts failed: %w", err)
	}
	defer rows.Close()

	var out contractsubscription.LinkList
	for rows.Next() {
		var name, dataJSON string
		if err := rows.Scan(&name, &dataJSON); err != nil {
			return contractsubscription.LinkList{}, fmt.Errorf("scan subscription contract failed: %w", err)
		}
		link, err := decodeSubscriptionLink(name, dataJSON)
		if err != nil {
			return contractsubscription.LinkList{}, err
		}
		out.Items = append(out.Items, link)
	}
	if err := rows.Err(); err != nil {
		return contractsubscription.LinkList{}, fmt.Errorf("iterate subscription contracts failed: %w", err)
	}
	return out, nil
}

func (s *SubscriptionStore) SaveLinks(ctx context.Context, links []contractsubscription.Link, updatedAt int64) error {
	if s == nil || s.db == nil {
		return errors.New("subscription store database is nil")
	}
	if updatedAt == 0 {
		updatedAt = time.Now().Unix()
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin subscription save transaction failed: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	for _, link := range links {
		link = normalizeLink(link)
		if err := validateLink(link); err != nil {
			return err
		}
		dataJSON, err := json.Marshal(link)
		if err != nil {
			return fmt.Errorf("encode subscription %q failed: %w", link.Name, err)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO subscriptions(name, updated_at, data_json)
			VALUES (?, ?, ?)
			ON CONFLICT(name) DO UPDATE SET
				updated_at = excluded.updated_at,
				data_json = excluded.data_json
		`, link.Name, updatedAt, string(dataJSON)); err != nil {
			return fmt.Errorf("upsert subscription %q failed: %w", link.Name, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit subscription save transaction failed: %w", err)
	}
	return nil
}

func (s *SubscriptionStore) DeleteLinks(ctx context.Context, names []string) error {
	return s.DeleteLinksWithOptions(ctx, contractsubscription.DeleteLinksRequest{Names: names})
}

func (s *SubscriptionStore) DeleteImpact(ctx context.Context, names []string) (contractsubscription.DeleteImpact, error) {
	if s == nil || s.db == nil {
		return contractsubscription.DeleteImpact{}, errors.New("subscription store database is nil")
	}
	names = uniqueNames(names)
	if len(names) == 0 {
		return contractsubscription.DeleteImpact{}, nil
	}
	placeholders, args := namedPlaceholders(names)
	var impact contractsubscription.DeleteImpact
	if err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(DISTINCT node_id)
		FROM subscription_nodes_v2
		WHERE subscription_name IN (`+placeholders+`)
	`, args...).Scan(&impact.Nodes); err != nil {
		return contractsubscription.DeleteImpact{}, fmt.Errorf("count subscription nodes failed: %w", err)
	}
	if err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(DISTINCT user_id)
		FROM subscription_users_v2 su
		JOIN users_v2 u ON u.id = su.user_id
		WHERE su.subscription_name IN (`+placeholders+`) AND u.origin = 'migrated'
	`, args...).Scan(&impact.Users); err != nil {
		return contractsubscription.DeleteImpact{}, fmt.Errorf("count subscription users failed: %w", err)
	}
	return impact, nil
}

func (s *SubscriptionStore) DeleteLinksWithOptions(ctx context.Context, request contractsubscription.DeleteLinksRequest) error {
	if s == nil || s.db == nil {
		return errors.New("subscription store database is nil")
	}
	names := uniqueNames(request.Names)
	if len(names) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin subscription delete transaction failed: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	placeholders, args := namedPlaceholders(names)
	var nodeIDs []string
	rows, err := tx.QueryContext(ctx, `SELECT DISTINCT node_id FROM subscription_nodes_v2 WHERE subscription_name IN (`+placeholders+`)`, args...)
	if err != nil {
		return fmt.Errorf("query subscription nodes before delete failed: %w", err)
	}
	for rows.Next() {
		var nodeID string
		if err := rows.Scan(&nodeID); err != nil {
			_ = rows.Close()
			return fmt.Errorf("scan subscription node before delete failed: %w", err)
		}
		nodeIDs = append(nodeIDs, nodeID)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return fmt.Errorf("iterate subscription nodes before delete failed: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close subscription nodes before delete failed: %w", err)
	}
	var userIDs []string
	rows, err = tx.QueryContext(ctx, `SELECT DISTINCT user_id FROM subscription_users_v2 WHERE subscription_name IN (`+placeholders+`)`, args...)
	if err != nil {
		return fmt.Errorf("query subscription users before delete failed: %w", err)
	}
	for rows.Next() {
		var userID string
		if err := rows.Scan(&userID); err != nil {
			_ = rows.Close()
			return fmt.Errorf("scan subscription user before delete failed: %w", err)
		}
		userIDs = append(userIDs, userID)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return fmt.Errorf("iterate subscription users before delete failed: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close subscription users before delete failed: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM subscription_nodes_v2 WHERE subscription_name IN (`+placeholders+`)`, args...); err != nil {
		return fmt.Errorf("unlink subscription nodes failed: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM subscription_users_v2 WHERE subscription_name IN (`+placeholders+`)`, args...); err != nil {
		return fmt.Errorf("unlink subscription users failed: %w", err)
	}
	if request.DeleteNodes {
		for _, nodeID := range nodeIDs {
			var references int
			if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM subscription_nodes_v2 WHERE node_id = ?`, nodeID).Scan(&references); err != nil {
				return fmt.Errorf("check remaining subscriptions for node %q failed: %w", nodeID, err)
			}
			if references != 0 {
				continue
			}
			if _, err := tx.ExecContext(ctx, `DELETE FROM node_tags_v2 WHERE EXISTS (SELECT 1 FROM json_each(node_tags_v2.members_json) WHERE value = ?)`, nodeID); err != nil {
				return fmt.Errorf("delete tags for node %q failed: %w", nodeID, err)
			}
			if _, err := tx.ExecContext(ctx, `DELETE FROM nodes_v2 WHERE id = ?`, nodeID); err != nil {
				return fmt.Errorf("delete subscription node %q failed: %w", nodeID, err)
			}
		}
	}
	if request.DeleteUsers {
		references, err := nodeUserReferences(ctx, tx)
		if err != nil {
			return err
		}
		for _, userID := range userIDs {
			var origin string
			if err := tx.QueryRowContext(ctx, `SELECT origin FROM users_v2 WHERE id = ?`, userID).Scan(&origin); errors.Is(err, sql.ErrNoRows) {
				continue
			} else if err != nil {
				return fmt.Errorf("read subscription user %q before delete failed: %w", userID, err)
			}
			if origin != string(contractuser.OriginMigrated) || references[userID] != 0 {
				continue
			}
			var remaining int
			if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM subscription_users_v2 WHERE user_id = ?`, userID).Scan(&remaining); err != nil {
				return fmt.Errorf("check remaining subscriptions for user %q failed: %w", userID, err)
			}
			if remaining != 0 {
				continue
			}
			if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM user_migration_sources_v2 WHERE user_id = ?`, userID).Scan(&remaining); err != nil {
				return fmt.Errorf("check migration sources for user %q failed: %w", userID, err)
			}
			if remaining != 0 {
				continue
			}
			if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM user_migration_dedup_v2 WHERE user_id = ?`, userID).Scan(&remaining); err != nil {
				return fmt.Errorf("check migration dedup for user %q failed: %w", userID, err)
			}
			if remaining == 0 {
				if _, err := tx.ExecContext(ctx, `DELETE FROM users_v2 WHERE id = ?`, userID); err != nil {
					return fmt.Errorf("delete subscription user %q failed: %w", userID, err)
				}
			}
		}
	}
	for _, name := range names {
		if _, err := tx.ExecContext(ctx, `DELETE FROM subscriptions WHERE name = ?`, name); err != nil {
			return fmt.Errorf("delete subscription %q failed: %w", name, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit subscription delete transaction failed: %w", err)
	}
	return nil
}

func uniqueNames(names []string) []string {
	seen := make(map[string]struct{}, len(names))
	result := make([]string, 0, len(names))
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		result = append(result, name)
	}
	return result
}

func namedPlaceholders(names []string) (string, []any) {
	placeholders := make([]string, len(names))
	args := make([]any, len(names))
	for i, name := range names {
		placeholders[i], args[i] = "?", name
	}
	return strings.Join(placeholders, ","), args
}

func nodeUserReferences(ctx context.Context, queryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}) (map[string]int, error) {
	references := make(map[string]int)
	rows, err := queryer.QueryContext(ctx, `SELECT data_json FROM nodes_v2`)
	if err != nil {
		return nil, fmt.Errorf("query node user references failed: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, fmt.Errorf("scan node user references failed: %w", err)
		}
		var node contractnode.Node
		if err := json.Unmarshal([]byte(data), &node); err != nil {
			return nil, fmt.Errorf("decode node user references failed: %w", err)
		}
		countProtocolReferences(references, node.Chain)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate node user references failed: %w", err)
	}
	return references, nil
}

func (s *SubscriptionStore) GetLink(ctx context.Context, name string) (contractsubscription.Link, bool, error) {
	if s == nil || s.db == nil {
		return contractsubscription.Link{}, false, errors.New("subscription store database is nil")
	}
	var dataJSON string
	err := s.db.QueryRowContext(ctx, `
		SELECT data_json
		FROM subscriptions
		WHERE name = ?
	`, name).Scan(&dataJSON)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return contractsubscription.Link{}, false, nil
	case err != nil:
		return contractsubscription.Link{}, false, fmt.Errorf("query subscription %q failed: %w", name, err)
	}
	link, err := decodeSubscriptionLink(name, dataJSON)
	if err != nil {
		return contractsubscription.Link{}, false, err
	}
	return link, true, nil
}

func (s *SubscriptionStore) ListPublishes(ctx context.Context) (contractsubscription.PublishList, error) {
	if s == nil || s.db == nil {
		return contractsubscription.PublishList{}, errors.New("subscription store database is nil")
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT name, data_json
		FROM publishes
		ORDER BY name
	`)
	if err != nil {
		return contractsubscription.PublishList{}, fmt.Errorf("query publish contracts failed: %w", err)
	}
	defer rows.Close()

	var out contractsubscription.PublishList
	for rows.Next() {
		var name, dataJSON string
		if err := rows.Scan(&name, &dataJSON); err != nil {
			return contractsubscription.PublishList{}, fmt.Errorf("scan publish contract failed: %w", err)
		}
		publish, err := decodePublish(name, dataJSON)
		if err != nil {
			return contractsubscription.PublishList{}, err
		}
		out.Items = append(out.Items, publish)
	}
	if err := rows.Err(); err != nil {
		return contractsubscription.PublishList{}, fmt.Errorf("iterate publish contracts failed: %w", err)
	}
	return out, nil
}

func (s *SubscriptionStore) SavePublish(ctx context.Context, publish contractsubscription.Publish, updatedAt int64) error {
	if s == nil || s.db == nil {
		return errors.New("subscription store database is nil")
	}
	publish = normalizePublish(publish)
	if strings.TrimSpace(publish.Name) == "" {
		return errors.New("publish name is empty")
	}
	if updatedAt == 0 {
		updatedAt = time.Now().Unix()
	}
	dataJSON, err := json.Marshal(publish)
	if err != nil {
		return fmt.Errorf("encode publish %q failed: %w", publish.Name, err)
	}
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO publishes(name, updated_at, data_json)
		VALUES (?, ?, ?)
		ON CONFLICT(name) DO UPDATE SET
			updated_at = excluded.updated_at,
			data_json = excluded.data_json
	`, publish.Name, updatedAt, string(dataJSON)); err != nil {
		return fmt.Errorf("upsert publish %q failed: %w", publish.Name, err)
	}
	return nil
}

func (s *SubscriptionStore) DeletePublish(ctx context.Context, name string) error {
	if s == nil || s.db == nil {
		return errors.New("subscription store database is nil")
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM publishes WHERE name = ?`, name)
	if err != nil {
		return fmt.Errorf("delete publish %q failed: %w", name, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: publish %s not found", ErrNotFound, name)
	}
	return nil
}

func (s *SubscriptionStore) ResolvePublish(ctx context.Context, name, path, password string) (contractsubscription.ResolvePublishResponse, error) {
	if s == nil || s.db == nil {
		return contractsubscription.ResolvePublishResponse{}, errors.New("subscription store database is nil")
	}
	var dataJSON string
	err := s.db.QueryRowContext(ctx, `
		SELECT data_json
		FROM publishes
		WHERE name = ?
	`, name).Scan(&dataJSON)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return contractsubscription.ResolvePublishResponse{}, nil
	case err != nil:
		return contractsubscription.ResolvePublishResponse{}, fmt.Errorf("query publish %q failed: %w", name, err)
	}
	publish, err := decodePublish(name, dataJSON)
	if err != nil {
		return contractsubscription.ResolvePublishResponse{}, err
	}
	if publish.Path != path {
		return contractsubscription.ResolvePublishResponse{}, nil
	}
	if subtle.ConstantTimeCompare([]byte(publish.Password), []byte(password)) != 1 {
		return contractsubscription.ResolvePublishResponse{}, nil
	}
	out := contractsubscription.ResolvePublishResponse{
		Points: make([]contractnode.Node, 0, len(publish.Points)),
	}
	for _, id := range publish.Points {
		node, err := getNodeContract(ctx, s.db, id)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return contractsubscription.ResolvePublishResponse{}, err
		}
		out.Points = append(out.Points, node)
	}
	return out, nil
}

func decodeSubscriptionLink(name, dataJSON string) (contractsubscription.Link, error) {
	var link contractsubscription.Link
	if err := json.Unmarshal([]byte(dataJSON), &link); err != nil {
		return contractsubscription.Link{}, fmt.Errorf("decode subscription %q failed: %w", name, err)
	}
	link = normalizeLink(link)
	if link.Name == "" {
		link.Name = name
	}
	if err := validateLink(link); err != nil {
		return contractsubscription.Link{}, fmt.Errorf("stored subscription %q is invalid: %w", name, err)
	}
	return link, nil
}

func decodePublish(name, dataJSON string) (contractsubscription.Publish, error) {
	var publish contractsubscription.Publish
	if err := json.Unmarshal([]byte(dataJSON), &publish); err != nil {
		return contractsubscription.Publish{}, fmt.Errorf("decode publish %q failed: %w", name, err)
	}
	publish = normalizePublish(publish)
	if publish.Name == "" {
		publish.Name = name
	}
	if strings.TrimSpace(publish.Name) == "" {
		return contractsubscription.Publish{}, fmt.Errorf("stored publish %q is invalid: publish name is empty", name)
	}
	return publish, nil
}

func normalizeLink(link contractsubscription.Link) contractsubscription.Link {
	link.Name = strings.TrimSpace(link.Name)
	link.URL = strings.TrimSpace(link.URL)
	if strings.TrimSpace(link.Type) == "" {
		link.Type = "reserve"
	}
	return link
}

func validateLink(link contractsubscription.Link) error {
	if strings.TrimSpace(link.Name) == "" {
		return errors.New("subscription name is empty")
	}
	if strings.TrimSpace(link.URL) == "" {
		return fmt.Errorf("subscription %q url is empty", link.Name)
	}
	return nil
}

func normalizePublish(publish contractsubscription.Publish) contractsubscription.Publish {
	publish.Name = strings.TrimSpace(publish.Name)
	if publish.Points == nil {
		publish.Points = []string{}
	}
	return publish
}
