package statistics

import (
	"context"
	"database/sql"
	"strconv"
	"sync"
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
	defer func() { _ = tx.Rollback() }()
	now := time.Now().Unix()
	if err = s.storeEncoded(ctx, tx, id, info, data, now); err != nil {
		return err
	}
	if err = h.pushEncoded(ctx, tx, info, data, now); err != nil {
		return err
	}
	return tx.Commit()
}

const (
	connectionPersistenceDelay = 750 * time.Millisecond
	connectionPersistenceBatch = 32
)

type connectionPersistence struct {
	db      *sql.DB
	session *sqliteInfoStore
	history *SQLiteHistory

	mu       sync.Mutex
	upserts  map[uint64]contractconnection.Connection
	deletes  map[uint64]struct{}
	historyQ []contractconnection.Connection
	overlay  map[uint64]contractconnection.Connection

	trigger chan struct{}
	stop    chan struct{}
	done    chan struct{}
}

func newConnectionPersistence(db *sql.DB, session *sqliteInfoStore, history *SQLiteHistory) *connectionPersistence {
	if db == nil || session == nil || history == nil {
		return nil
	}
	p := &connectionPersistence{
		db:      db,
		session: session,
		history: history,
		upserts: make(map[uint64]contractconnection.Connection),
		deletes: make(map[uint64]struct{}),
		overlay: make(map[uint64]contractconnection.Connection),
		trigger: make(chan struct{}, 1),
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
	}
	go p.run()
	return p
}

func (p *connectionPersistence) Store(id uint64, info contractconnection.Connection) {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.upserts[id] = info
	delete(p.deletes, id)
	p.overlay[id] = info
	p.historyQ = append(p.historyQ, info)
	flushNow := len(p.historyQ) >= connectionPersistenceBatch
	p.mu.Unlock()
	p.signal(flushNow)
}

func (p *connectionPersistence) Delete(id uint64) {
	if p == nil {
		return
	}
	p.mu.Lock()
	if _, pending := p.upserts[id]; pending {
		delete(p.upserts, id)
	} else {
		p.deletes[id] = struct{}{}
	}
	delete(p.overlay, id)
	p.mu.Unlock()
	p.signal(false)
}

func (p *connectionPersistence) Overlay(infos []contractconnection.Connection) {
	if p == nil || len(infos) == 0 {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for i := range infos {
		id, err := strconv.ParseUint(infos[i].ID, 10, 64)
		if err != nil {
			continue
		}
		if info, ok := p.overlay[id]; ok {
			infos[i] = info
		}
	}
}

func (p *connectionPersistence) signal(immediate bool) {
	select {
	case p.trigger <- struct{}{}:
	default:
	}
	if immediate {
		// The worker drains the same coalesced trigger; no second channel or
		// per-connection timer is needed.
	}
}

func (p *connectionPersistence) run() {
	defer close(p.done)
	var timer *time.Timer
	var timerC <-chan time.Time
	stopTimer := func() {
		if timer != nil {
			timer.Stop()
			timer = nil
			timerC = nil
		}
	}
	defer stopTimer()

	for {
		select {
		case <-p.stop:
			_ = p.flush()
			return
		case <-p.trigger:
			p.mu.Lock()
			flushNow := len(p.historyQ) >= connectionPersistenceBatch
			p.mu.Unlock()
			if flushNow {
				stopTimer()
				if err := p.flush(); err != nil {
					log.Warn("batch persist connections failed", "err", err)
				}
				continue
			}
			if timer == nil {
				timer = time.NewTimer(connectionPersistenceDelay)
				timerC = timer.C
			}
		case <-timerC:
			if err := p.flush(); err != nil {
				log.Warn("batch persist connections failed", "err", err)
			}
			timer = nil
			timerC = nil
		}
	}
}

func (p *connectionPersistence) flush() error {
	p.mu.Lock()
	if len(p.upserts) == 0 && len(p.deletes) == 0 && len(p.historyQ) == 0 {
		p.mu.Unlock()
		return nil
	}
	upserts := p.upserts
	deletes := p.deletes
	historyQ := p.historyQ
	p.upserts = make(map[uint64]contractconnection.Connection)
	p.deletes = make(map[uint64]struct{})
	p.historyQ = nil
	p.mu.Unlock()

	ctx := context.Background()
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		p.requeue(upserts, deletes, historyQ)
		return err
	}
	defer func() { _ = tx.Rollback() }()
	now := time.Now().Unix()
	encoded := make(map[string]string, len(upserts))
	for id, info := range upserts {
		data, err := encodeStatisticJSON(&info)
		if err != nil {
			p.requeue(upserts, deletes, historyQ)
			return err
		}
		encoded[info.ID] = data
		if err := p.session.storeEncoded(ctx, tx, id, info, data, now); err != nil {
			p.requeue(upserts, deletes, historyQ)
			return err
		}
	}
	for id := range deletes {
		if err := execStatisticStatement(ctx, tx, p.session.deleteStmt, p.db, deleteSessionSQL, id); err != nil {
			p.requeue(upserts, deletes, historyQ)
			return err
		}
	}
	for _, info := range historyQ {
		data, ok := encoded[info.ID]
		if !ok {
			var err error
			data, err = encodeStatisticJSON(&info)
			if err != nil {
				p.requeue(upserts, deletes, historyQ)
				return err
			}
		}
		if err := p.history.pushEncoded(ctx, tx, info, data, now); err != nil {
			p.requeue(upserts, deletes, historyQ)
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		p.requeue(upserts, deletes, historyQ)
		return err
	}

	p.mu.Lock()
	for id := range upserts {
		if current, ok := p.overlay[id]; ok && current.ID == upserts[id].ID {
			delete(p.overlay, id)
		}
	}
	p.mu.Unlock()
	return nil
}

func (p *connectionPersistence) requeue(upserts map[uint64]contractconnection.Connection, deletes map[uint64]struct{}, historyQ []contractconnection.Connection) {
	p.mu.Lock()
	for id, info := range upserts {
		if _, deleted := p.deletes[id]; !deleted {
			if _, newer := p.upserts[id]; !newer {
				p.upserts[id] = info
			}
		}
	}
	for id := range deletes {
		if _, newer := p.upserts[id]; !newer {
			p.deletes[id] = struct{}{}
		}
	}
	p.historyQ = append(historyQ, p.historyQ...)
	p.mu.Unlock()
}

func (p *connectionPersistence) Close() error {
	if p == nil {
		return nil
	}
	close(p.stop)
	<-p.done
	return nil
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
