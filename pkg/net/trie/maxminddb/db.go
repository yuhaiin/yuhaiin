package maxminddb

import (
	"context"
	"errors"
	"maps"
	"net/netip"
	"slices"
	"sync"
	"unsafe"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/oschwald/maxminddb-golang/v2"
	"github.com/oschwald/maxminddb-golang/v2/mmdbdata"
)

var _ (netapi.MaxMindDB) = (*MaxMindDB)(nil)

type MaxMindDB struct {
	countries func() ([]string, error)
	db        *maxminddb.Reader
	closed    bool
	mu        sync.RWMutex
}

func NewMaxMindDB(path string) (*MaxMindDB, error) {
	db, err := maxminddb.Open(path)
	if err != nil {
		return nil, err
	}
	return &MaxMindDB{db: db, countries: sync.OnceValues(func() ([]string, error) { return readCountries(db) })}, nil
}

// Countries enumerates each record once per loaded database. The returned slice
// belongs to the caller; neither API clients nor a database reload can mutate it.
func (m *MaxMindDB) Countries() ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.closed {
		return nil, errors.New("maxminddb closed")
	}
	codes, err := m.countries()
	return slices.Clone(codes), err
}

func readCountries(db *maxminddb.Reader) ([]string, error) {
	codes := map[string]struct{}{}
	seen := map[uintptr]struct{}{}
	for result := range db.Networks() {
		if err := result.Err(); err != nil {
			return nil, err
		}
		offset := result.Offset()
		if _, ok := seen[offset]; ok {
			continue
		}
		seen[offset] = struct{}{}
		var country FastCountry
		if err := result.Decode(&country); err != nil {
			return nil, err
		}
		if country.CountryISO != "" {
			codes[country.CountryISO] = struct{}{}
		}
	}
	return slices.Sorted(maps.Keys(codes)), nil
}

func (m *MaxMindDB) Lookup(ip netip.Addr) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return "", errors.New("maxminddb closed")
	}

	var country FastCountry
	err := m.db.Lookup(ip).Decode(&country)
	return country.CountryISO, err
}

func (m *MaxMindDB) LookupAddr(ctx context.Context, addr netapi.Address) (string, error) {
	if !addr.IsFqdn() {
		return m.Lookup(addr.(netapi.IPAddress).AddrPort().Addr())
	}

	ips, err := netapi.GetContext(ctx).ConnOptions().RouteIPs(ctx, addr)
	if err != nil {
		return "", errors.New("not found geoip")
	}

	for ip := range ips.Iter() {
		add, ok := netip.AddrFromSlice(ip)
		if !ok {
			continue
		}

		mark, err := m.Lookup(add)
		if err == nil {
			return mark, nil
		}
	}

	return "", errors.New("not found geoip")
}

type FastCountry struct {
	CountryISO string
}

func (c *FastCountry) UnmarshalMaxMindDB(d *mmdbdata.Decoder) error {
	mapIter, size, err := d.ReadMap()
	if err != nil {
		return err
	}
	// Pre-allocate with correct capacity for better performance
	_ = size // Use for pre-allocation if storing map data
	for key, err := range mapIter {
		if err != nil {
			return err
		}
		switch unsafe.String(unsafe.SliceData(key), len(key)) {
		case "country":
			countryIter, _, err := d.ReadMap()
			if err != nil {
				return err
			}
			for countryKey, countryErr := range countryIter {
				if countryErr != nil {
					return countryErr
				}
				if unsafe.String(unsafe.SliceData(countryKey), len(countryKey)) == "iso_code" {
					c.CountryISO, err = d.ReadString()
					return err
				} else {
					if err := d.SkipValue(); err != nil {
						return err
					}
				}
			}
		default:
			if err := d.SkipValue(); err != nil {
				return err
			}
		}
	}
	return nil
}

func (m *MaxMindDB) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.closed = true
	return m.db.Close()
}
