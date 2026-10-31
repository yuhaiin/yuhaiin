// Package quota provides live, hierarchical byte reservations. Persistence is
// performed by one bounded background worker, never by TryReserve or Commit.
package quota

import (
	"context"
	"errors"
	"math"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/contract/resource"
)

const (
	GrantBytes          = uint64(4 << 20)
	MaxReservationBytes = 64 << 10
	MaxWindows          = 262144
	MaxBindings         = 198 // Three windows for a user, credential and 64 groups.
)

var (
	ErrExhausted = errors.New("traffic quota exhausted")
	ErrFunding   = errors.New("traffic quota awaiting durable credit")
	ErrBusy      = errors.New("traffic quota persistence queue full")
	ErrClosed    = errors.New("traffic quota ledger closed")
	ErrExpired   = errors.New("traffic quota window expired")
	ErrRetired   = errors.New("traffic quota state is retiring")
)

type Direction uint8

const (
	Upload Direction = iota
	Download
)

// Amounts are independent upload, download and combined counters. Following a
// crash the conservative combined charge need not equal upload plus download.
type Amounts [3]uint64

type Key struct {
	Scope, ScopeID, QuotaID, Period string
	StartsAt                        int64
}

type Record struct {
	OwnerUserID       string
	Key               Key
	Measured, Charged Amounts
	// Alert bits use percentages, so reordering configured thresholds cannot
	// generate duplicate events within the same window.
	Alerts [2]uint64
	Denied uint64
}

// Store.Save must atomically persist a batch, using the maximum of each saved
// counter and bitwise OR of alert bits. Retrying a committed batch is idempotent.
// Only one live Ledger may own a Store; this is not a distributed quota service.
type Store interface {
	Load(context.Context, Key) (Record, error)
	Save(context.Context, []Record) error
	Reclaim(context.Context, []Reclaim) error
}

// Reclaim returns unused credit after admissions stop and all reservations in
// the window settle. MaxCharged includes a possibly committed, unacknowledged
// funding request. A Store must reject counters outside these expected bounds.
type Reclaim struct {
	Record     Record
	MaxCharged Amounts
}

type Binding struct {
	Scope, ScopeID string
	OwnerUserID    string
	Quota          resource.Quota
}

type Event struct {
	OwnerUserID string
	Key         Key
	At          int64
	Threshold   int
}

type Diagnostics struct {
	Windows, Pending                           int
	Denied, PersistenceFailures, DroppedEvents uint64
}

func Window(period string, now time.Time) (start, end int64, err error) {
	now = now.UTC()
	switch period {
	case "daily":
		at := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
		return at.Unix(), at.AddDate(0, 0, 1).Unix(), nil
	case "monthly":
		at := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
		return at.Unix(), at.AddDate(0, 1, 0).Unix(), nil
	case "lifetime":
		return 0, 0, nil
	default:
		return 0, 0, errors.New("invalid quota period")
	}
}

func add(a, b uint64) uint64 { return a + min(b, math.MaxInt64-a) }

func bytesContract(a Amounts) resource.Bytes {
	return resource.Bytes{Upload: decimal(a[0]), Download: decimal(a[1]), Combined: decimal(a[2])}
}
