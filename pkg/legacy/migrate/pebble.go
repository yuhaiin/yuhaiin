package migrate

import (
	"context"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/cache"
)

var (
	legacyDownloadKey = []byte("DOWNLOAD")
	legacyUploadKey   = []byte("UPLOAD")
)

const legacyFakeIPCursorKey = "reserved_cursor_state"

// MigrateLegacyPebble imports every persisted Pebble value used by the old
// runtime. It must run during application startup, before runtime stores open.
func MigrateLegacyPebble(ctx context.Context, db *sql.DB, legacy cache.Cache, ipv4, ipv6 netip.Prefix) error {
	if db == nil || legacy == nil {
		return nil
	}
	if err := MigrateLegacyTotalFlow(ctx, db, legacy.NewCache("flow_data")); err != nil {
		return err
	}
	if err := MigrateLegacyFakeIP(ctx, db, ipv4, legacy); err != nil {
		return err
	}
	return MigrateLegacyFakeIP(ctx, db, ipv6, legacy)
}

// MigrateLegacyTotalFlow imports the old Pebble flow counters once.
func MigrateLegacyTotalFlow(ctx context.Context, db *sql.DB, legacy cache.Geter) error {
	if db == nil || legacy == nil {
		return nil
	}

	done, err := legacyMetadata(ctx, db, "legacy_total_flow_import_done")
	if err != nil || done == "1" {
		return err
	}

	download, upload, err := sqliteTotals(ctx, db)
	if err != nil {
		return err
	}
	if download != 0 || upload != 0 {
		return setLegacyMetadata(ctx, db, map[string]string{
			"legacy_total_flow_import_done":   "1",
			"legacy_total_flow_import_source": "existing_sqlite",
		})
	}

	download, err = legacyFlowValue(legacy, legacyDownloadKey)
	if err != nil {
		return fmt.Errorf("load legacy download total: %w", err)
	}
	upload, err = legacyFlowValue(legacy, legacyUploadKey)
	if err != nil {
		return fmt.Errorf("load legacy upload total: %w", err)
	}

	source := "missing"
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if download != 0 || upload != 0 {
		now := time.Now().Unix()
		for key, value := range map[string]uint64{
			"total_download": download,
			"total_upload":   upload,
		} {
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO statistics_kv(key, value_int, updated_at)
				VALUES (?, ?, ?)
				ON CONFLICT(key) DO UPDATE SET
					value_int = excluded.value_int,
					updated_at = excluded.updated_at
			`, key, value, now); err != nil {
				return err
			}
		}
		source = "pebble_flow_data"
	}

	if err := setLegacyMetadataTx(ctx, tx, map[string]string{
		"legacy_total_flow_import_done":   "1",
		"legacy_total_flow_import_source": source,
	}); err != nil {
		return err
	}
	return tx.Commit()
}

// MigrateLegacyFakeIP imports both the old prefix bucket and old LRU bucket
// for one FakeIP family. It is idempotent through a per-prefix marker.
func MigrateLegacyFakeIP(ctx context.Context, db *sql.DB, prefix netip.Prefix, legacy cache.Cache) error {
	if db == nil || legacy == nil {
		return nil
	}

	prefix = prefix.Masked()
	family := fakeIPFamily(prefix)
	prefixKey := prefix.String()
	marker := fmt.Sprintf("fakeip_legacy_imported:%d:%s", family, prefixKey)
	done, err := legacyMetadata(ctx, db, marker)
	if err != nil || done == "1" {
		return err
	}

	entries, cursorIndex, cursorAddr, hasCursor, err := collectLegacyFakeIPEntries(prefix, legacy)
	if err != nil {
		return err
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now().UnixNano()
	for _, entry := range entries {
		if _, err := tx.ExecContext(ctx, `
			DELETE FROM fakeip_entries
			WHERE family = ? AND prefix = ? AND ip = ? AND domain <> ?
		`, family, prefixKey, entry.addr.AsSlice(), entry.domain); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO fakeip_entries(family, prefix, domain, ip, created_at, last_used_at)
			VALUES (?, ?, ?, ?, ?, ?)
			ON CONFLICT(family, prefix, domain) DO UPDATE SET
				ip = excluded.ip,
				last_used_at = excluded.last_used_at
		`, family, prefixKey, entry.domain, entry.addr.AsSlice(), now, now); err != nil {
			return err
		}
	}
	if hasCursor {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO fakeip_cursors(family, prefix, cursor_ip, cursor_idx, updated_at)
			VALUES (?, ?, ?, ?, ?)
			ON CONFLICT(family, prefix) DO UPDATE SET
				cursor_ip = excluded.cursor_ip,
				cursor_idx = excluded.cursor_idx,
				updated_at = excluded.updated_at
		`, family, prefixKey, cursorAddr.AsSlice(), cursorIndex, now); err != nil {
			return err
		}
	}
	if err := setLegacyMetadataTx(ctx, tx, map[string]string{marker: "1"}); err != nil {
		return err
	}
	return tx.Commit()
}

type legacyFakeIPEntry struct {
	domain string
	addr   netip.Addr
}

func collectLegacyFakeIPEntries(prefix netip.Prefix, legacy cache.Cache) ([]legacyFakeIPEntry, uint64, netip.Addr, bool, error) {
	byDomain := map[string]netip.Addr{}
	var cursorIndex uint64
	var cursorAddr netip.Addr
	var hasCursor bool

	buckets := []string{prefix.String(), "fakedns_cache"}
	if fakeIPFamily(prefix) == 6 {
		buckets = []string{prefix.String(), "fakedns_cachev6"}
	}
	for _, name := range buckets {
		bucket := legacy.NewCache(name)
		if name == prefix.String() {
			if index, addr, ok := legacyFakeIPCursor(prefix, bucket); ok {
				cursorIndex, cursorAddr, hasCursor = index, addr, true
			}
		}
		if err := bucket.Range(func(key, value []byte) bool {
			if string(key) == legacyFakeIPCursorKey {
				return true
			}
			addr, ok := netip.AddrFromSlice(value)
			if ok && prefix.Contains(addr) {
				byDomain[string(key)] = addr
			}
			return true
		}); err != nil && !errors.Is(err, cache.ErrBucketNotExist) {
			return nil, 0, netip.Addr{}, false, err
		}
	}

	domains := make([]string, 0, len(byDomain))
	for domain := range byDomain {
		domains = append(domains, domain)
	}
	sort.Strings(domains)
	entries := make([]legacyFakeIPEntry, 0, len(domains))
	for _, domain := range domains {
		entries = append(entries, legacyFakeIPEntry{domain: domain, addr: byDomain[domain]})
	}
	return entries, cursorIndex, cursorAddr, hasCursor, nil
}

func legacyFakeIPCursor(prefix netip.Prefix, bucket cache.Geter) (uint64, netip.Addr, bool) {
	value, err := bucket.Get([]byte(legacyFakeIPCursorKey))
	if err != nil || len(value) <= 8 {
		return 0, netip.Addr{}, false
	}
	addr, ok := netip.AddrFromSlice(value[8:])
	if !ok || !prefix.Contains(addr) {
		return 0, netip.Addr{}, false
	}
	return binary.BigEndian.Uint64(value[:8]), addr, true
}

func fakeIPFamily(prefix netip.Prefix) int {
	if prefix.Addr().Unmap().Is6() {
		return 6
	}
	return 4
}

func legacyFlowValue(legacy cache.Geter, key []byte) (uint64, error) {
	data, err := legacy.Get(key)
	if err != nil {
		return 0, err
	}
	if len(data) < 8 {
		return 0, nil
	}
	return binary.BigEndian.Uint64(data), nil
}

func sqliteTotals(ctx context.Context, db *sql.DB) (uint64, uint64, error) {
	var download, upload uint64
	for _, total := range []struct {
		key   string
		value *uint64
	}{
		{key: "total_download", value: &download},
		{key: "total_upload", value: &upload},
	} {
		err := db.QueryRowContext(ctx, `SELECT value_int FROM statistics_kv WHERE key = ?`, total.key).Scan(total.value)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return 0, 0, err
		}
	}
	return download, upload, nil
}

func legacyMetadata(ctx context.Context, db *sql.DB, key string) (string, error) {
	var value string
	err := db.QueryRowContext(ctx, `SELECT value FROM metadata WHERE key = ?`, key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return value, err
}

func setLegacyMetadata(ctx context.Context, db *sql.DB, values map[string]string) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := setLegacyMetadataTx(ctx, tx, values); err != nil {
		return err
	}
	return tx.Commit()
}

func setLegacyMetadataTx(ctx context.Context, tx *sql.Tx, values map[string]string) error {
	for key, value := range values {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO metadata(key, value)
			VALUES (?, ?)
			ON CONFLICT(key) DO UPDATE SET value = excluded.value
		`, key, value); err != nil {
			return err
		}
	}
	return nil
}
