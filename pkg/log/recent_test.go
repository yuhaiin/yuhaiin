package log

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRecentReturnsNewestMatchingLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "yuhaiin.log")
	var content strings.Builder
	for i := range 50 {
		level := "INFO"
		if i%10 == 0 {
			level = "ERROR"
		}
		fmt.Fprintf(&content, "time=t%02d level=%s msg=\"line %02d\" host=Example.COM\n", i, level, i)
	}
	content.WriteString("unstructured tail line\n")
	if err := os.WriteFile(path, []byte(content.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	c := NewController()
	c.path = path

	all, err := c.Recent(t.Context(), RecentQuery{Limit: 3})
	if err != nil || len(all.Lines) != 3 || !all.Truncated || all.Partial || all.Lines[2] != "unstructured tail line" || !strings.Contains(all.Lines[0], "line 48") {
		t.Fatalf("recent = %+v %v", all, err)
	}
	errorLevel := slog.LevelError
	errorsOnly, _ := c.Recent(t.Context(), RecentQuery{Limit: 100, MinLevel: &errorLevel})
	// Lines without a level are kept.
	if len(errorsOnly.Lines) != 6 || errorsOnly.Truncated || !strings.Contains(errorsOnly.Lines[0], "line 00") {
		t.Fatalf("errors = %+v", errorsOnly)
	}
	matching, _ := c.Recent(t.Context(), RecentQuery{Limit: 100, Contains: "LINE 2"})
	if len(matching.Lines) != 10 {
		t.Fatalf("contains = %+v", matching)
	}
	empty, err := (&Controller{}).Recent(t.Context(), RecentQuery{})
	if err != nil || len(empty.Lines) != 0 {
		t.Fatal(empty, err)
	}
}

func TestRecentReadsOnlyTheEndOfLargeLogs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "yuhaiin.log")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	line := strings.Repeat("x", 1023) + "\n"
	for range (recentLogWindow / len(line)) + 100 {
		_, _ = f.WriteString(line)
	}
	_, _ = f.WriteString("level=WARN msg=last\n")
	_ = f.Close()
	c := NewController()
	c.path = path
	result, err := c.Recent(t.Context(), RecentQuery{Limit: 2})
	if err != nil || !result.Partial || len(result.Lines) != 2 || result.Lines[1] != "level=WARN msg=last" || len(result.Lines[0]) != 1023 {
		t.Fatalf("result = partial %v lines %d %v", result.Partial, len(result.Lines), err)
	}
}
