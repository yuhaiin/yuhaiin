package statistics

import (
	"context"
	"database/sql"
	"time"

	contractconnection "github.com/Asutorufa/yuhaiin/pkg/contract/connection"
	"github.com/Asutorufa/yuhaiin/pkg/log"
)

func prepareStatisticStatement(db *sql.DB, query string) *sql.Stmt {
	if db == nil {
		return nil
	}
	stmt, err := db.PrepareContext(context.Background(), query)
	if err != nil {
		log.Warn("prepare statistic statement failed", "err", err)
	}
	return stmt
}

func closeStatisticStatement(stmt *sql.Stmt) error {
	if stmt == nil {
		return nil
	}
	return stmt.Close()
}

func execStatisticStatement(ctx context.Context, tx *sql.Tx, stmt *sql.Stmt, db *sql.DB, query string, args ...any) error {
	var err error
	switch {
	case tx != nil && stmt != nil:
		_, err = tx.StmtContext(ctx, stmt).ExecContext(ctx, args...)
	case tx != nil:
		_, err = tx.ExecContext(ctx, query, args...)
	case stmt != nil:
		_, err = stmt.ExecContext(ctx, args...)
	default:
		_, err = db.ExecContext(ctx, query, args...)
	}
	return err
}

// Session metadata and history contain the same connection JSON. Encode it
// once and commit both records atomically, avoiding duplicate serialization
// and an additional SQLite commit on every connection open.
func storeSQLiteConnection(s *sqliteInfoStore, h *SQLiteHistory, id uint64, info contractconnection.Connection) error {
	if s.db == nil {
		return nil
	}
	data, err := encodeStatisticJSON(&info)
	if err != nil {
		return err
	}
	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().Unix()
	if err = s.storeEncoded(ctx, tx, id, info, data, now); err != nil {
		return err
	}
	if err = h.pushEncoded(ctx, tx, info, data, now); err != nil {
		return err
	}
	return tx.Commit()
}

// Read one SQLite snapshot rather than one query per active connection.
// Runtime membership filters orphaned rows; missing/invalid metadata retains
// the existing ID-only fallback. SQLite remains the metadata source of truth.
func (s *sqliteInfoStore) loadMany(ids []uint64) []contractconnection.Connection {
	infos := make([]contractconnection.Connection, len(ids))
	positions := make(map[uint64]int, len(ids))
	for i, id := range ids {
		positions[id] = i
		infos[i].ID = formatUint64(id)
	}
	if s.db == nil || len(ids) == 0 {
		return infos
	}
	rows, err := s.db.QueryContext(context.Background(), `SELECT id, summary_json FROM connection_sessions`)
	if err != nil {
		log.Warn("load sqlite connection sessions failed", "err", err)
		return infos
	}
	defer rows.Close()
	for rows.Next() {
		var id uint64
		var data string
		if err := rows.Scan(&id, &data); err != nil {
			log.Warn("scan sqlite connection session failed", "err", err)
			continue
		}
		i, ok := positions[id]
		if !ok {
			continue
		}
		var info contractconnection.Connection
		if err := decodeStatisticJSON(data, &info); err != nil {
			log.Warn("decode sqlite connection session failed", "id", id, "err", err)
			continue
		}
		infos[i] = info
	}
	if err := rows.Err(); err != nil {
		log.Warn("read sqlite connection sessions failed", "err", err)
	}
	return infos
}
