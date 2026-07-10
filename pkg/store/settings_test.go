package store

import "testing"

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
