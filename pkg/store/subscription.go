package store

import (
	"context"
	"database/sql"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"strings"
	"time"

	contractsubscription "github.com/Asutorufa/yuhaiin/pkg/contract/subscription"
	"github.com/Asutorufa/yuhaiin/pkg/log"
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
			log.Warn("skip invalid stored subscription", "name", name, "err", err)
			continue
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
		merged, err := mergeProtected(ctx, tx, link, `SELECT data_json FROM subscriptions WHERE name=?`, link.Name)
		if err != nil {
			return err
		}
		link = merged
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
