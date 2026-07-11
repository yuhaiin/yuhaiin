package store

import (
	"context"
	"path/filepath"
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
	ctx := context.Background()
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
