// Package sqlitetest provides database fixture helpers for tests.
package sqlitetest

import (
	"context"
	"database/sql"
)

// Exec runs an explicit sequence of statements, stopping at the first error.
// Each SQL string must contain one statement; trigger bodies stay intact.
func Exec(ctx context.Context, db interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}, statements ...string) (sql.Result, error) {
	var result sql.Result
	var err error
	for _, statement := range statements {
		result, err = db.ExecContext(ctx, statement)
		if err != nil {
			return result, err
		}
	}
	return result, nil
}
