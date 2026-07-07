package fakeip

import (
	"context"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/cache"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	storagesqlite "github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
)

const (
	sqliteFakeIPTouchInterval      = 5 * time.Minute
	sqliteFakeIPTouchFlushInterval = time.Second
	cursorKey                      = "reserved_cursor_state"
)

type SQLiteFakeIPPool struct {
	store            *storagesqlite.Store
	db               *sql.DB
	lookupDomainStmt *sql.Stmt
	lookupIPStmt     *sql.Stmt
	current          netip.Addr
	prefix           netip.Prefix
	key              string
	family           int
	index            uint64
	maxNum           uint64
	mu               sync.Mutex
	touchMu          sync.Mutex
	touchDomains     map[string]int64
	touchIPs         map[netip.Addr]int64
	touchStop        chan struct{}
	touchDone        chan struct{}
	closeOnce        sync.Once
}

type legacyFakeIPEntry struct {
	domain string
	addr   netip.Addr
}

func NewSQLiteFakeIPPool(path string, prefix netip.Prefix, maxNum int, legacy ...cache.Cache) (*SQLiteFakeIPPool, error) {
	store, err := storagesqlite.Open(context.Background(), path)
	if err != nil {
		return nil, err
	}

	pool, err := newSQLiteFakeIPPool(store.DB(), prefix, maxNum, legacy...)
	if err != nil {
		_ = store.Close()
		return nil, err
	}
	pool.store = store
	return pool, nil
}

func newSQLiteFakeIPPool(db *sql.DB, prefix netip.Prefix, maxNum int, legacy ...cache.Cache) (*SQLiteFakeIPPool, error) {
	if db == nil {
		return nil, errors.New("sqlite fakeip db is nil")
	}
	if maxNum <= 0 {
		maxNum = 65536
	}

	prefix = prefix.Masked()
	hostBits := prefix.Addr().BitLen() - prefix.Bits()
	if hostBits < 64 {
		totalIPs := uint64(1) << hostBits
		if uint64(maxNum) > totalIPs {
			maxNum = int(totalIPs)
		}
	}

	pool := &SQLiteFakeIPPool{
		db:      db,
		prefix:  prefix,
		key:     prefix.String(),
		family:  fakeIPFamily(prefix),
		maxNum:  uint64(maxNum),
		current: prefix.Addr().Prev(),
	}
	if len(legacy) > 0 && legacy[0] != nil {
		if err := pool.importLegacy(context.Background(), legacy[0]); err != nil {
			return nil, err
		}
	}
	if err := pool.loadCursor(context.Background()); err != nil {
		return nil, err
	}
	if err := pool.prepare(context.Background()); err != nil {
		return nil, err
	}
	pool.startTouchWorker()
	return pool, nil
}

func (p *SQLiteFakeIPPool) prepare(ctx context.Context) error {
	var err error
	p.lookupDomainStmt, err = p.db.PrepareContext(ctx, `
		SELECT ip, last_used_at
		FROM fakeip_entries
		WHERE family = ? AND prefix = ? AND domain = ?
	`)
	if err != nil {
		return err
	}

	p.lookupIPStmt, err = p.db.PrepareContext(ctx, `
		SELECT domain, last_used_at
		FROM fakeip_entries
		WHERE family = ? AND prefix = ? AND ip = ?
	`)
	if err != nil {
		_ = p.lookupDomainStmt.Close()
		p.lookupDomainStmt = nil
		return err
	}

	return nil
}

func (p *SQLiteFakeIPPool) startTouchWorker() {
	p.touchDomains = map[string]int64{}
	p.touchIPs = map[netip.Addr]int64{}
	p.touchStop = make(chan struct{})
	p.touchDone = make(chan struct{})
	go p.runTouchWorker()
}

func (p *SQLiteFakeIPPool) runTouchWorker() {
	ticker := time.NewTicker(sqliteFakeIPTouchFlushInterval)
	defer ticker.Stop()
	defer close(p.touchDone)

	for {
		select {
		case <-ticker.C:
			_ = p.flushTouches(context.Background())
		case <-p.touchStop:
			_ = p.flushTouches(context.Background())
			return
		}
	}
}

func fakeIPFamily(prefix netip.Prefix) int {
	if prefix.Addr().Unmap().Is6() {
		return 6
	}
	return 4
}

func (p *SQLiteFakeIPPool) importLegacy(ctx context.Context, legacy cache.Cache) error {
	done, err := p.legacyImportDone(ctx)
	if err != nil {
		return err
	}
	if done {
		return nil
	}

	start := time.Now()
	log.Info("scan legacy fakeip cache", "prefix", p.key, "family", p.family)
	entries, cursorIndex, cursorAddr, hasCursor, err := p.collectLegacyEntries(legacy)
	if err != nil {
		return err
	}

	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now()
	for _, entry := range entries {
		if err := p.storeEntry(ctx, tx, entry.domain, entry.addr, now); err != nil {
			return err
		}
	}

	if hasCursor {
		p.index = cursorIndex
		p.current = cursorAddr
		if err := p.saveCursor(ctx, tx, now); err != nil {
			return err
		}
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO metadata(key, value)
		VALUES (?, '1')
		ON CONFLICT(key) DO UPDATE SET value = excluded.value
	`, p.legacyImportKey()); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	log.Info(
		"import legacy fakeip cache finished",
		"prefix", p.key,
		"family", p.family,
		"entries", len(entries),
		"cursor", hasCursor,
		"elapsed", time.Since(start),
	)
	return nil
}

func (p *SQLiteFakeIPPool) legacyImportDone(ctx context.Context) (bool, error) {
	var value string
	err := p.db.QueryRowContext(ctx, `
		SELECT value
		FROM metadata
		WHERE key = ?
	`, p.legacyImportKey()).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return value == "1", nil
}

func (p *SQLiteFakeIPPool) legacyImportKey() string {
	return fmt.Sprintf("fakeip_legacy_imported:%d:%s", p.family, p.key)
}

func (p *SQLiteFakeIPPool) collectLegacyEntries(legacy cache.Cache) ([]legacyFakeIPEntry, uint64, netip.Addr, bool, error) {
	byDomain := map[string]netip.Addr{}
	var cursorIndex uint64
	var cursorAddr netip.Addr
	var hasCursor bool

	for _, bucketName := range p.legacyBucketNames() {
		bucket := legacy.NewCache(bucketName)
		if bucketName == p.key {
			if idx, addr, ok := p.loadLegacyCursor(bucket); ok {
				cursorIndex = idx
				cursorAddr = addr
				hasCursor = true
			}
		}

		err := bucket.Range(func(key []byte, value []byte) bool {
			if string(key) == cursorKey {
				return true
			}
			domain, addr, ok := p.parseLegacyEntry(key, value)
			if ok {
				byDomain[domain] = addr
			}
			return true
		})
		if err != nil && !errors.Is(err, cache.ErrBucketNotExist) {
			return nil, 0, netip.Addr{}, false, err
		}
	}

	entries := make([]legacyFakeIPEntry, 0, len(byDomain))
	for domain, addr := range byDomain {
		entries = append(entries, legacyFakeIPEntry{domain: domain, addr: addr})
	}
	return entries, cursorIndex, cursorAddr, hasCursor, nil
}

func (p *SQLiteFakeIPPool) legacyBucketNames() []string {
	if p.family == 6 {
		return []string{p.key, "fakedns_cachev6"}
	}
	return []string{p.key, "fakedns_cache"}
}

func (p *SQLiteFakeIPPool) loadLegacyCursor(bucket cache.Cache) (uint64, netip.Addr, bool) {
	value, err := bucket.Get([]byte(cursorKey))
	if err != nil || len(value) <= 8 {
		return 0, netip.Addr{}, false
	}

	addr, ok := netip.AddrFromSlice(value[8:])
	if !ok || !p.prefix.Contains(addr) {
		return 0, netip.Addr{}, false
	}

	return binary.BigEndian.Uint64(value[:8]), addr, true
}

func (p *SQLiteFakeIPPool) parseLegacyEntry(key []byte, value []byte) (string, netip.Addr, bool) {
	addr, ok := netip.AddrFromSlice(value)
	if !ok || !p.prefix.Contains(addr) {
		return "", netip.Addr{}, false
	}

	return string(key), addr, true
}

func (p *SQLiteFakeIPPool) Close() error {
	if p == nil {
		return nil
	}
	var err error
	p.closeOnce.Do(func() {
		if p.touchStop != nil {
			close(p.touchStop)
			<-p.touchDone
		}
		if p.lookupDomainStmt != nil {
			if e := p.lookupDomainStmt.Close(); e != nil && err == nil {
				err = e
			}
		}
		if p.lookupIPStmt != nil {
			if e := p.lookupIPStmt.Close(); e != nil && err == nil {
				err = e
			}
		}
		if p.store != nil {
			if e := p.store.Close(); e != nil && err == nil {
				err = e
			}
		}
	})
	return err
}

func (p *SQLiteFakeIPPool) Prefix() netip.Prefix {
	return p.prefix
}

func (p *SQLiteFakeIPPool) GetFakeIPForDomain(domain string) netip.Addr {
	ctx := context.Background()
	now := time.Now()
	if ip, ok := p.getIP(ctx, domain, now); ok {
		return ip
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	now = time.Now()
	if ip, ok := p.getIP(ctx, domain, now); ok {
		return ip
	}

	ip, err := p.allocate(ctx, domain, now)
	if err != nil {
		return netip.Addr{}
	}
	return ip
}

func (p *SQLiteFakeIPPool) GetDomainFromIP(ip netip.Addr) (string, bool) {
	if !p.prefix.Contains(ip) {
		return "", false
	}

	now := time.Now()
	var domain string
	var lastUsedAt int64
	err := p.lookupIPStmt.QueryRowContext(context.Background(), p.family, p.key, ip.AsSlice()).Scan(&domain, &lastUsedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false
	}
	if err != nil {
		return "", false
	}

	p.touchIP(ip, now, lastUsedAt)
	return domain, true
}

func (p *SQLiteFakeIPPool) getIP(ctx context.Context, domain string, now time.Time) (netip.Addr, bool) {
	var ipBytes []byte
	var lastUsedAt int64
	err := p.lookupDomainStmt.QueryRowContext(ctx, p.family, p.key, domain).Scan(&ipBytes, &lastUsedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return netip.Addr{}, false
	}
	if err != nil {
		return netip.Addr{}, false
	}

	ip, ok := netip.AddrFromSlice(ipBytes)
	if !ok || !p.prefix.Contains(ip) {
		_ = p.deleteDomain(ctx, domain)
		return netip.Addr{}, false
	}

	p.touchDomain(domain, now, lastUsedAt)
	return ip, true
}

func (p *SQLiteFakeIPPool) shouldTouch(now time.Time, lastUsedAt int64) bool {
	return now.UnixNano()-lastUsedAt >= sqliteFakeIPTouchInterval.Nanoseconds()
}

func (p *SQLiteFakeIPPool) touchDomain(domain string, now time.Time, lastUsedAt int64) {
	if !p.shouldTouch(now, lastUsedAt) {
		return
	}

	p.touchMu.Lock()
	p.touchDomains[domain] = now.UnixNano()
	p.touchMu.Unlock()
}

func (p *SQLiteFakeIPPool) touchIP(ip netip.Addr, now time.Time, lastUsedAt int64) {
	if !p.shouldTouch(now, lastUsedAt) {
		return
	}

	p.touchMu.Lock()
	p.touchIPs[ip] = now.UnixNano()
	p.touchMu.Unlock()
}

func (p *SQLiteFakeIPPool) flushTouches(ctx context.Context) error {
	p.touchMu.Lock()
	if len(p.touchDomains) == 0 && len(p.touchIPs) == 0 {
		p.touchMu.Unlock()
		return nil
	}

	domains := p.touchDomains
	ips := p.touchIPs
	p.touchDomains = map[string]int64{}
	p.touchIPs = map[netip.Addr]int64{}
	p.touchMu.Unlock()

	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	for domain, lastUsedAt := range domains {
		if _, err := tx.ExecContext(ctx, `
			UPDATE fakeip_entries
			SET last_used_at = ?
			WHERE family = ? AND prefix = ? AND domain = ?
		`, lastUsedAt, p.family, p.key, domain); err != nil {
			return err
		}
	}

	for ip, lastUsedAt := range ips {
		if _, err := tx.ExecContext(ctx, `
			UPDATE fakeip_entries
			SET last_used_at = ?
			WHERE family = ? AND prefix = ? AND ip = ?
		`, lastUsedAt, p.family, p.key, ip.AsSlice()); err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (p *SQLiteFakeIPPool) deleteDomain(ctx context.Context, domain string) error {
	_, err := p.db.ExecContext(ctx, `
		DELETE FROM fakeip_entries
		WHERE family = ? AND prefix = ? AND domain = ?
	`, p.family, p.key, domain)
	return err
}

func (p *SQLiteFakeIPPool) loadCursor(ctx context.Context) error {
	var idx uint64
	var ipBytes []byte
	err := p.db.QueryRowContext(ctx, `
		SELECT cursor_idx, cursor_ip
		FROM fakeip_cursors
		WHERE family = ? AND prefix = ?
	`, p.family, p.key).Scan(&idx, &ipBytes)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("load fakeip sqlite cursor failed: %w", err)
	}

	addr, ok := netip.AddrFromSlice(ipBytes)
	if ok && p.prefix.Contains(addr) {
		p.index = idx
		p.current = addr
	}
	return nil
}

func (p *SQLiteFakeIPPool) allocate(ctx context.Context, domain string, now time.Time) (netip.Addr, error) {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return netip.Addr{}, err
	}
	defer func() { _ = tx.Rollback() }()

	count, err := p.entryCount(ctx, tx)
	if err != nil {
		return netip.Addr{}, err
	}

	var addr netip.Addr
	if count >= p.maxNum {
		addr, err = p.evictLRU(ctx, tx)
		if err != nil {
			return netip.Addr{}, err
		}
	} else {
		addr, err = p.nextAvailable(ctx, tx)
		if err != nil {
			return netip.Addr{}, err
		}
	}

	if err := p.storeEntry(ctx, tx, domain, addr, now); err != nil {
		return netip.Addr{}, err
	}
	if err := p.saveCursor(ctx, tx, now); err != nil {
		return netip.Addr{}, err
	}
	if err := tx.Commit(); err != nil {
		return netip.Addr{}, err
	}
	return addr, nil
}

func (p *SQLiteFakeIPPool) entryCount(ctx context.Context, tx *sql.Tx) (uint64, error) {
	var count uint64
	err := tx.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM fakeip_entries
		WHERE family = ? AND prefix = ?
	`, p.family, p.key).Scan(&count)
	return count, err
}

func (p *SQLiteFakeIPPool) evictLRU(ctx context.Context, tx *sql.Tx) (netip.Addr, error) {
	var domain string
	var ipBytes []byte
	err := tx.QueryRowContext(ctx, `
		SELECT domain, ip
		FROM fakeip_entries
		WHERE family = ? AND prefix = ?
		ORDER BY last_used_at ASC, created_at ASC
		LIMIT 1
	`, p.family, p.key).Scan(&domain, &ipBytes)
	if err != nil {
		return netip.Addr{}, err
	}
	addr, ok := netip.AddrFromSlice(ipBytes)
	if !ok || !p.prefix.Contains(addr) {
		return netip.Addr{}, errors.New("invalid fakeip lru address")
	}
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM fakeip_entries
		WHERE family = ? AND prefix = ? AND domain = ?
	`, p.family, p.key, domain); err != nil {
		return netip.Addr{}, err
	}
	return addr, nil
}

func (p *SQLiteFakeIPPool) nextAvailable(ctx context.Context, tx *sql.Tx) (netip.Addr, error) {
	limit := p.maxNum
	if limit == 0 {
		limit = 1
	}
	for range limit {
		addr := p.rotateNext()
		if !p.ipExists(ctx, tx, addr) {
			return addr, nil
		}
	}
	return p.evictLRU(ctx, tx)
}

func (p *SQLiteFakeIPPool) rotateNext() netip.Addr {
	next := p.current.Next()
	p.index++

	if !p.prefix.Contains(next) || p.index > p.maxNum {
		p.current = p.prefix.Addr()
		p.index = 1
		return p.current
	}

	p.current = next
	return p.current
}

func (p *SQLiteFakeIPPool) ipExists(ctx context.Context, tx *sql.Tx, addr netip.Addr) bool {
	var exists int
	err := tx.QueryRowContext(ctx, `
		SELECT 1
		FROM fakeip_entries
		WHERE family = ? AND prefix = ? AND ip = ?
		LIMIT 1
	`, p.family, p.key, addr.AsSlice()).Scan(&exists)
	return err == nil
}

func (p *SQLiteFakeIPPool) storeEntry(ctx context.Context, tx *sql.Tx, domain string, addr netip.Addr, now time.Time) error {
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM fakeip_entries
		WHERE family = ? AND prefix = ? AND ip = ? AND domain <> ?
	`, p.family, p.key, addr.AsSlice(), domain); err != nil {
		return err
	}

	_, err := tx.ExecContext(ctx, `
		INSERT INTO fakeip_entries(family, prefix, domain, ip, created_at, last_used_at)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(family, prefix, domain) DO UPDATE SET
			ip = excluded.ip,
			last_used_at = excluded.last_used_at
	`, p.family, p.key, domain, addr.AsSlice(), now.UnixNano(), now.UnixNano())
	return err
}

func (p *SQLiteFakeIPPool) saveCursor(ctx context.Context, tx *sql.Tx, now time.Time) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO fakeip_cursors(family, prefix, cursor_ip, cursor_idx, updated_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(family, prefix) DO UPDATE SET
			cursor_ip = excluded.cursor_ip,
			cursor_idx = excluded.cursor_idx,
			updated_at = excluded.updated_at
	`, p.family, p.key, p.current.AsSlice(), p.index, now.UnixNano())
	return err
}
