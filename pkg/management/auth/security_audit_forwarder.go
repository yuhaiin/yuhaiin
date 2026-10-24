package auth

import (
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

type auditSender interface {
	send(context.Context, auditConfiguration, []AuditRecord) error
}

// AuditForwarder owns one bounded worker. Only management events enter its
// durable outbox; traffic events and packet processing never call it.
type AuditForwarder struct {
	store   *Store
	sender  auditSender
	ctx     context.Context
	cancel  context.CancelFunc
	ready   chan struct{}
	done    chan struct{}
	epoch   atomic.Uint64
	mu      sync.Mutex
	attempt context.CancelFunc
}

func newAuditForwarder(ctx context.Context, s *Store, sender auditSender) (*AuditForwarder, error) {
	cfg, err := readAuditConfiguration(ctx, s.db)
	if err != nil {
		return nil, err
	}
	if !validAuditSettings(cfg.AuditSettings) {
		return nil, ErrInvalid
	}
	if sender == nil {
		sender = networkAuditSender{}
	}
	ctx, cancel := context.WithCancel(ctx)
	f := &AuditForwarder{store: s, sender: sender, ctx: ctx, cancel: cancel, ready: make(chan struct{}, 1), done: make(chan struct{})}
	if !s.auditForwarder.CompareAndSwap(nil, f) {
		cancel()
		return nil, ErrConflict
	}
	go f.run()
	f.wake()
	return f, nil
}
func (f *AuditForwarder) wake() {
	select {
	case f.ready <- struct{}{}:
	default:
	}
}
func (f *AuditForwarder) changed() {
	f.epoch.Add(1)
	f.mu.Lock()
	if f.attempt != nil {
		f.attempt()
	}
	f.mu.Unlock()
	f.wake()
}
func (f *AuditForwarder) Close() error { f.cancel(); <-f.done; return nil }
func (f *AuditForwarder) run() {
	defer close(f.done)
	defer f.store.auditForwarder.CompareAndSwap(f, nil)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	delay := time.Duration(0)
	next := time.Time{}
	epoch := f.epoch.Load()
	for {
		select {
		case <-f.ctx.Done():
			return
		case <-ticker.C:
		case <-f.ready:
		}
		if current := f.epoch.Load(); current != epoch {
			epoch = current
			next = time.Time{}
			delay = 0
		}
		if time.Now().Before(next) {
			continue
		}
		more, err := f.drain(f.ctx)
		if err != nil {
			delay = min(max(5*time.Second, delay*2), 5*time.Minute)
			next = time.Now().Add(delay)
		} else {
			delay = 0
			next = time.Time{}
			if more {
				f.wake()
			}
		}
	}
}

func (f *AuditForwarder) localFailure(err error) (bool, error) {
	f.store.auditFailures.Add(1)
	return false, err
}

func (f *AuditForwarder) drain(ctx context.Context) (bool, error) {
	epoch := f.epoch.Load()
	tx, err := f.store.db.BeginTx(ctx, nil)
	if err != nil {
		return f.localFailure(err)
	}
	defer func() { _ = tx.Rollback() }()
	cfg, err := readAuditConfiguration(ctx, tx)
	if err != nil {
		return f.localFailure(err)
	}
	if err = pruneAudit(ctx, tx, cfg.AuditSettings, time.Now().Unix()); err != nil {
		return f.localFailure(err)
	}
	records := []AuditRecord{}
	if cfg.ForwardEnabled {
		rows, queryErr := tx.QueryContext(ctx, `SELECT payload FROM management_audit_outbox ORDER BY event_id LIMIT 64`)
		if queryErr != nil {
			return f.localFailure(queryErr)
		}
		for rows.Next() {
			var raw string
			if err = rows.Scan(&raw); err != nil {
				break
			}
			var record AuditRecord
			if err = json.Unmarshal([]byte(raw), &record); err != nil {
				break
			}
			records = append(records, record)
		}
		err = errors.Join(err, rows.Err(), rows.Close())
		if err != nil {
			return f.localFailure(err)
		}
	}
	if err = tx.Commit(); err != nil {
		return f.localFailure(err)
	}
	if len(records) == 0 {
		return false, nil
	}
	attempt, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	f.mu.Lock()
	f.attempt = cancel
	if epoch != f.epoch.Load() {
		cancel()
	}
	f.mu.Unlock()
	err = f.sender.send(attempt, cfg, records)
	f.mu.Lock()
	f.attempt = nil
	f.mu.Unlock()
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	if epoch != f.epoch.Load() {
		return true, nil
	}
	ack, ackErr := f.store.db.BeginTx(ctx, nil)
	if ackErr != nil {
		return f.localFailure(ackErr)
	}
	defer func() { _ = ack.Rollback() }()
	var revision uint64
	if ackErr = ack.QueryRowContext(ctx, `SELECT revision FROM management_audit_settings WHERE id=1`).Scan(&revision); ackErr != nil {
		return f.localFailure(ackErr)
	}
	if revision != cfg.Revision {
		return true, nil
	}
	if err != nil {
		// Fixed local classifications only: never persist remote response bodies,
		// URLs, headers or authentication tokens in failure diagnostics.
		_, ackErr = ack.ExecContext(ctx, `UPDATE management_audit_delivery SET failures=failures+1,last_failure=?,last_error=? WHERE id=1`, time.Now().Unix(), auditDeliveryReason(err))
	} else {
		for _, r := range records {
			var id int64
			id, ackErr = strconv.ParseInt(r.ID, 10, 64)
			if ackErr != nil {
				break
			}
			_, ackErr = ack.ExecContext(ctx, `DELETE FROM management_audit_outbox WHERE event_id=?`, id)
			if ackErr != nil {
				break
			}
		}
		if ackErr == nil {
			_, ackErr = ack.ExecContext(ctx, `UPDATE management_audit_delivery SET delivered=delivered+?,last_success=?,last_error='' WHERE id=1`, len(records), time.Now().Unix())
		}
	}
	if ackErr != nil {
		return f.localFailure(ackErr)
	}
	if ackErr = ack.Commit(); ackErr != nil {
		return f.localFailure(ackErr)
	}
	return len(records) == 64, err
}

var _ io.Closer = (*AuditForwarder)(nil)
