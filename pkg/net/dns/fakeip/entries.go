package fakeip

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	contractresolver "github.com/Asutorufa/yuhaiin/pkg/contract/resolver"
)

const DefaultPageSize = 25
const MaxPageSize = 100

// ListEntries reads only a bounded page from the active pools. A read transaction
// keeps the count and page consistent while DNS allocates or evicts mappings.
// Search matches a domain substring (literally, ignoring ASCII case) or a full IP.
func (f *FakeDNS) ListEntries(ctx context.Context, page, size int, query string) ([]contractresolver.FakeIPEntry, int, error) {
	p, ok := f.ipv4.(*SQLiteFakeIPPool)
	if !ok {
		return nil, 0, errors.New("fakeip storage is unavailable")
	}
	page = max(1, page)
	if size <= 0 {
		size = DefaultPageSize
	}
	size = min(size, MaxPageSize)
	ranges := f.Ranges()
	where := `WHERE family = ? AND prefix = ?`
	args := []any{4, ranges[0].String()}
	query = strings.ToLower(strings.TrimSpace(query))
	if query != "" {
		where += ` AND (instr(lower(domain), ?) > 0 OR ip = ?)`
		var ipBytes []byte
		if ip, err := netip.ParseAddr(query); err == nil && ip.Zone() == "" {
			ipBytes = ip.Unmap().AsSlice()
		}
		args = append(args, query, ipBytes)
	}
	// Each branch walks its primary-key index in domain order. UNION ALL lets
	// SQLite merge these streams without sorting every stored mapping.
	union := `SELECT family, domain, ip FROM fakeip_entries ` + where + ` UNION ALL SELECT family, domain, ip FROM fakeip_entries ` + where
	second := append([]any{6, ranges[1].String()}, args[2:]...)
	args = append(args, second...)
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = tx.Rollback() }()
	var total int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM (`+union+`)`, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	items := make([]contractresolver.FakeIPEntry, 0)
	// Check before multiplying, including for an arbitrarily large client page.
	if total == 0 || page-1 > (total-1)/size {
		return items, total, nil
	}
	args = append(args, size, (page-1)*size)
	rows, err := tx.QueryContext(ctx, union+` ORDER BY family, domain LIMIT ? OFFSET ?`, args...)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var item contractresolver.FakeIPEntry
		var family int
		var raw []byte
		if err := rows.Scan(&family, &item.Domain, &raw); err != nil {
			return nil, 0, err
		}
		ip, ok := netip.AddrFromSlice(raw)
		if !ok {
			return nil, 0, fmt.Errorf("invalid stored fakeip for %q", item.Domain)
		}
		item.IP = ip.String()
		items = append(items, item)
	}
	return items, total, rows.Err()
}

// DeleteEntry includes the displayed domain and IP so a stale page cannot delete
// a different mapping after an eviction. Allocation uses the same pool lock.
func (f *FakeDNS) DeleteEntry(ctx context.Context, entry contractresolver.FakeIPEntry) (contractresolver.FakeIPDeleteResponse, error) {
	ip, err := netip.ParseAddr(entry.IP)
	if err != nil || ip.Zone() != "" {
		return contractresolver.FakeIPDeleteResponse{}, errors.New("invalid fakeip address")
	}
	ip = ip.Unmap()
	target := f.ipv4
	if ip.Is6() {
		target = f.ipv6
	}
	p, ok := target.(*SQLiteFakeIPPool)
	if !ok {
		return contractresolver.FakeIPDeleteResponse{}, errors.New("fakeip storage is unavailable")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	result, err := p.db.ExecContext(ctx, `DELETE FROM fakeip_entries WHERE family = ? AND prefix = ? AND domain = ? AND ip = ?`, p.family, p.key, entry.Domain, ip.AsSlice())
	if err != nil {
		return contractresolver.FakeIPDeleteResponse{}, err
	}
	removed, err := result.RowsAffected()
	if err == nil && removed > 0 {
		p.cache.removeDomain(entry.Domain)
	}
	return contractresolver.FakeIPDeleteResponse{Removed: int(removed)}, err
}
