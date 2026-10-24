package store

import (
	"context"
	"database/sql"
	"encoding/json/v2"
	"errors"

	"github.com/Asutorufa/yuhaiin/pkg/security/secret"
)

type secretRowReader interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// Called within the existing write transaction, so concurrent password edits
// cannot race a metadata-only save into restoring an older secret.
func mergeProtected[T any](ctx context.Context, query any, next T, statement string, args ...any) (T, error) {
	if _, managed := secret.FromContext(ctx); !managed {
		return next, nil
	}
	reader, ok := query.(secretRowReader)
	if !ok {
		var zero T
		return zero, errors.New("protected configuration requires transactional reads")
	}
	var encoded string
	var previous T
	err := reader.QueryRowContext(ctx, statement, args...).Scan(&encoded)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return previous, err
	}
	if err == nil {
		if err := json.Unmarshal([]byte(encoded), &previous); err != nil {
			return previous, err
		}
	}
	return secret.Merge(ctx, next, previous)
}

// Direct DB entry points acquire a transaction for protected writes. Callers
// already inside a transaction retain ownership of their commit/rollback.
func protectedTransaction(ctx context.Context, exec any, write func(any) error) (bool, error) {
	if _, managed := secret.FromContext(ctx); !managed {
		return false, nil
	}
	beginner, ok := exec.(interface {
		BeginTx(context.Context, *sql.TxOptions) (*sql.Tx, error)
	})
	if !ok {
		return false, nil
	}
	tx, err := beginner.BeginTx(ctx, nil)
	if err != nil {
		return true, err
	}
	defer func() { _ = tx.Rollback() }()
	if err := write(tx); err != nil {
		return true, err
	}
	return true, tx.Commit()
}
