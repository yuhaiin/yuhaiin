package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
)

var fakeDNSSharedListsMigration = Migration{Version: 26, Name: "fakedns_shared_lists", Transform: ConvertFakeDNSInlineLists}

// ConvertFakeDNSInlineLists moves inline FakeDNS whitelist and skip-check
// entries into shared host lists and references those lists instead. FakeDNS
// only reads list references, so this runs as a migration and again after a
// configuration backup restore, whose rows may predate the migration. It is a
// no-op when no inline entries remain.
func ConvertFakeDNSInlineLists(ctx context.Context, tx *sql.Tx) error {
	for _, kind := range []struct{ inline, ref, id, name string }{
		{"whitelist", "whitelist_list", "fakedns-whitelist", "FakeDNS whitelist"},
		{"skip_check", "skip_check_list", "fakedns-skip-check", "FakeDNS skip check"},
	} {
		values, err := fakeDNSInlineValues(ctx, tx, kind.inline)
		if err != nil {
			return err
		}
		if len(values) == 0 {
			continue
		}
		id, name, err := unusedSharedListName(ctx, tx, kind.id, kind.name)
		if err != nil {
			return err
		}
		data, err := json.Marshal(contractroute.RouteListDetail{
			Revision: 1, ID: id, Name: name, Type: "host",
			Source: contractroute.ListSource{Type: "local", Local: &contractroute.LocalSource{Lists: values}},
		})
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO route_lists_v2(id, name, owner_rule_id, list_type, source_type, updated_at, data_json)
			VALUES (?, ?, NULL, 'host', 'local', ?, ?)
		`, id, name, time.Now().Unix(), string(data)); err != nil {
			return fmt.Errorf("create FakeDNS list %q: %w", name, err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO dns_fakedns_lists(kind, value) VALUES (?, ?)`, kind.ref, id); err != nil {
			return fmt.Errorf("reference FakeDNS list %q: %w", name, err)
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM dns_fakedns_lists WHERE kind = ?`, kind.inline); err != nil {
			return fmt.Errorf("remove inline FakeDNS %s entries: %w", kind.inline, err)
		}
	}
	return nil
}

func fakeDNSInlineValues(ctx context.Context, tx *sql.Tx, kind string) ([]string, error) {
	rows, err := tx.QueryContext(ctx, `SELECT value FROM dns_fakedns_lists WHERE kind = ? ORDER BY rowid`, kind)
	if err != nil {
		return nil, fmt.Errorf("read inline FakeDNS %s entries: %w", kind, err)
	}
	defer rows.Close()
	var values []string
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, rows.Err()
}

// unusedSharedListName keeps a user's own list with the same ID or name intact.
// IDs are unique across all lists; names only among shared lists.
func unusedSharedListName(ctx context.Context, tx *sql.Tx, baseID, baseName string) (string, string, error) {
	id, err := firstUnused(ctx, tx, `SELECT 1 FROM route_lists_v2 WHERE id = ?`, baseID, "%s-%d")
	if err != nil {
		return "", "", err
	}
	name, err := firstUnused(ctx, tx, `SELECT 1 FROM route_lists_v2 WHERE name = ? AND owner_rule_id IS NULL`, baseName, "%s %d")
	return id, name, err
}

func firstUnused(ctx context.Context, tx *sql.Tx, query, base, format string) (string, error) {
	for n := 1; n <= 100; n++ {
		candidate := base
		if n > 1 {
			candidate = fmt.Sprintf(format, base, n)
		}
		var taken int
		err := tx.QueryRowContext(ctx, query, candidate).Scan(&taken)
		if errors.Is(err, sql.ErrNoRows) {
			return candidate, nil
		}
		if err != nil {
			return "", err
		}
	}
	return "", fmt.Errorf("no unused list identifier for %s", base)
}
