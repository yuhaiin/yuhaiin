package store

import (
	"path/filepath"
	"slices"
	"testing"

	contractsettings "github.com/Asutorufa/yuhaiin/pkg/contract/settings"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
)

func TestLogLevelCodeRoundTrip(t *testing.T) {
	levels := []struct {
		code  int32
		level string
	}{
		{0, "verbose"},
		{1, "debug"},
		{2, "info"},
		{3, "warning"},
		{4, "error"},
		{5, "fatal"},
	}
	for _, tt := range levels {
		if got := logLevelString(tt.code); got != tt.level {
			t.Errorf("logLevelString(%d) = %q, want %q", tt.code, got, tt.level)
		}
		if got := logLevelCode(tt.level); got != tt.code {
			t.Errorf("logLevelCode(%q) = %d, want %d", tt.level, got, tt.code)
		}
	}
	if got := logLevelCode("warn"); got != 3 {
		t.Errorf("logLevelCode(warn) = %d, want 3", got)
	}
}

func TestSettingsStorePprofDefaultsToEnabledAndPersists(t *testing.T) {
	ctx := t.Context()
	sqliteStore, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer sqliteStore.Close()

	store := NewSettingsStore(sqliteStore.DB())
	settings, err := store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !settings.Pprof {
		t.Fatal("pprof should preserve the legacy enabled default")
	}

	if _, err := store.Save(ctx, contractsettings.Settings{Pprof: false}); err != nil {
		t.Fatal(err)
	}
	settings, err = store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if settings.Pprof {
		t.Fatal("pprof setting was not persisted")
	}
}

func TestSettingsStoreTrustedOriginsPersistence(t *testing.T) {
	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "state.db")
	sqliteStore, err := sqlite.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sqliteStore.Close() }()

	store := NewSettingsStore(sqliteStore.DB())
	current, err := store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(current.TrustedOrigins) != 0 {
		t.Fatalf("unexpected initial custom origins: %v", current.TrustedOrigins)
	}
	current.TrustedOrigins = []string{"https://example.org:8443", "http://localhost:5173"}
	next, err := store.Save(ctx, current)
	if err != nil {
		t.Fatal(err)
	}
	if len(next.TrustedOrigins) != 2 {
		t.Fatalf("saved custom origins missing: %v", next.TrustedOrigins)
	}

	// Simulate a restart: close the SQLite handle entirely and reopen it.
	if err := sqliteStore.Close(); err != nil {
		t.Fatal(err)
	}
	sqliteStore, err = sqlite.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	store = NewSettingsStore(sqliteStore.DB())
	fresh, err := store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(fresh.TrustedOrigins, current.TrustedOrigins) {
		t.Fatalf("persisted after reopening=%v want=%v", fresh.TrustedOrigins, current.TrustedOrigins)
	}
	fresh.TrustedOrigins = nil
	if _, err := store.Save(ctx, fresh); err != nil {
		t.Fatal(err)
	}
	cleared, err := store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(cleared.TrustedOrigins) != 0 {
		t.Fatalf("custom origins not cleared: %v", cleared.TrustedOrigins)
	}
}
