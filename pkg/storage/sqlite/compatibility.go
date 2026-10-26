package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
)

// ErrIncompatibleSchema prevents a binary from silently accepting a newer,
// foreign or incomplete migration history. It is not permission to downgrade.
var ErrIncompatibleSchema = errors.New("incompatible SQLite schema; use a compatible binary or an offline recovery point")

type migrationReader interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func knownMigrations(kind string) ([]Migration, error) {
	switch kind {
	case "configuration":
		return migrations, nil
	case "management":
		return []Migration{managementAuthMigration, managementInitializationMigration, proxyCredentialsMigration, managementOAuthMigration, managementAuditMigration}, nil
	default:
		return nil, errors.New("unknown SQLite store kind")
	}
}

func SupportedSchemaVersion(kind string) (int, error) {
	known, err := knownMigrations(kind)
	if err != nil {
		return 0, err
	}
	return known[len(known)-1].Version, nil
}

func migrationPrefix(ctx context.Context, reader migrationReader, known []Migration) (count, last int, err error) {
	rows, err := reader.QueryContext(ctx, "SELECT CASE WHEN typeof(version)='integer' THEN version ELSE -1 END, substr(name,1,256) FROM migrate ORDER BY version LIMIT ?", len(known)+1)
	if err != nil {
		return 0, 0, err
	}
	defer rows.Close()
	for rows.Next() {
		var version int
		var name string
		if err := rows.Scan(&version, &name); err != nil {
			return 0, 0, err
		}
		if count >= len(known) || known[count].Version != version || known[count].Name != name {
			return 0, 0, ErrIncompatibleSchema
		}
		count++
		last = version
	}
	return count, last, rows.Err()
}

// Check before journal-mode changes and bootstrap writes. Empty databases and
// the empty base tables left before the first migration are valid. Existing
// stores must have an exact known prefix, including names and metadata version.
func checkStoreCompatibility(ctx context.Context, db *sql.DB, kind string) error {
	known, err := knownMigrations(kind)
	if err != nil {
		return err
	}
	var ordinary, tables int
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*'").Scan(&tables); err != nil {
		return err
	}
	if tables == 0 {
		return nil
	}
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_schema WHERE type='table' AND rootpage>0 AND name IN ('metadata','migrate')").Scan(&ordinary); err != nil {
		return err
	}
	if ordinary != 2 {
		return ErrIncompatibleSchema
	}
	count, last, err := migrationPrefix(ctx, db, known)
	if err != nil {
		return errors.Join(ErrIncompatibleSchema, err)
	}
	if count == 0 {
		if tables != 2 {
			return ErrIncompatibleSchema
		}
		var versions int
		if err := db.QueryRowContext(ctx, "SELECT count(*) FROM metadata WHERE key='schema_version'").Scan(&versions); err != nil {
			return err
		}
		if versions != 0 {
			return ErrIncompatibleSchema
		}
		return nil
	}
	var version string
	if err := db.QueryRowContext(ctx, "SELECT substr(value,1,64) FROM metadata WHERE key='schema_version'").Scan(&version); err != nil {
		return errors.Join(ErrIncompatibleSchema, err)
	}
	if version != strconv.Itoa(last) {
		return ErrIncompatibleSchema
	}
	return nil
}
