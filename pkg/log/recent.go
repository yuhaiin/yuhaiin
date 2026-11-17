package log

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"strings"
)

// Bounds of a recent-log read. Only the end of the current log file is read,
// so a large log never costs more than this much IO and memory.
const (
	recentLogWindow   = 4 << 20
	recentLogMaxLines = 1000
	recentLogMaxLine  = 8 << 10
)

// RecentQuery selects recent log lines.
type RecentQuery struct {
	// Limit is the maximum number of lines returned, newest last.
	Limit int
	// MinLevel keeps lines at or above this level. Lines without a level are kept.
	MinLevel *slog.Level
	// Contains keeps lines that contain this text, case-insensitively.
	Contains string
}

// RecentResult holds the newest matching lines in file order.
type RecentResult struct {
	Lines []string
	// Truncated reports that older matching lines exist in the window.
	Truncated bool
	// Partial reports that the file is longer than the window that was read.
	Partial bool
}

// Recent returns the newest lines of the current log file that match query,
// without subscribing to new lines.
func (l *Controller) Recent(ctx context.Context, query RecentQuery) (RecentResult, error) {
	if query.Limit <= 0 || query.Limit > recentLogMaxLines {
		query.Limit = recentLogMaxLines
	}
	l.wmu.RLock()
	path := l.path
	l.wmu.RUnlock()
	if path == "" {
		return RecentResult{}, nil
	}
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return RecentResult{}, nil
	}
	if err != nil {
		return RecentResult{}, err
	}
	defer f.Close()
	stat, err := f.Stat()
	if err != nil {
		return RecentResult{}, err
	}
	var result RecentResult
	start := max(stat.Size()-recentLogWindow, 0)
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return RecentResult{}, err
	}
	reader := bufio.NewReaderSize(io.LimitReader(f, stat.Size()-start), 64<<10)
	if start > 0 {
		result.Partial = true
		// The first line of the window is probably incomplete.
		if _, err := reader.ReadString('\n'); err != nil {
			return result, nil
		}
	}
	contains := strings.ToLower(query.Contains)
	ring := make([]string, 0, query.Limit)
	next := 0
	for {
		if err := ctx.Err(); err != nil {
			return RecentResult{}, err
		}
		line, err := reader.ReadString('\n')
		if line = trimLineBreak(line); line != "" && matchesRecent(line, query.MinLevel, contains) {
			if len(line) > recentLogMaxLine {
				line = line[:recentLogMaxLine] + "…"
			}
			if len(ring) < query.Limit {
				ring = append(ring, line)
			} else {
				ring[next] = line
				next = (next + 1) % query.Limit
				result.Truncated = true
			}
		}
		if err != nil {
			break
		}
	}
	result.Lines = append(ring[next:], ring[:next]...)
	return result, nil
}

func matchesRecent(line string, minimum *slog.Level, contains string) bool {
	if contains != "" && !strings.Contains(strings.ToLower(line), contains) {
		return false
	}
	if minimum == nil {
		return true
	}
	_, rest, found := strings.Cut(line, "level=")
	if !found {
		return true
	}
	level, _, _ := strings.Cut(rest, " ")
	return SLogLevel(level) >= *minimum
}
