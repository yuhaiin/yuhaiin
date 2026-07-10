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
	if s == nil || s.db == nil {
		return errors.New("subscription store database is nil")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin subscription delete transaction failed: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
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
