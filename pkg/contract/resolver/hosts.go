package resolver

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

var ErrInvalidHostEntry = errors.New("invalid host mapping")

// HostEntry is one configured mapping. Targets may be IPs or host aliases,
// including the existing port-specific mapping syntax.
type HostEntry struct {
	Host   string `json:"host"`
	Target string `json:"target"`
}

func (h HostEntry) Validate() error {
	if h.Host == "" || h.Target == "" || strings.TrimSpace(h.Host) != h.Host || strings.TrimSpace(h.Target) != h.Target || strings.ContainsAny(h.Host+h.Target, " \t\r\n/\\?#@") {
		return fmt.Errorf("%w: host and target must be non-empty addresses without whitespace or URL syntax", ErrInvalidHostEntry)
	}
	return nil
}

// HostEntries keeps directory reads and individual changes separate from the
// full hosts snapshot used by initialization and configuration export.
type HostEntries interface {
	ListHostEntries(context.Context, int, int, string) ([]HostEntry, int, error)
	HostEntry(context.Context, string) (HostEntry, error)
	SaveHostEntry(context.Context, HostEntry, bool) (HostEntry, error)
	DeleteHostEntry(context.Context, string) error
}
