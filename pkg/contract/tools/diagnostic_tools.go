package tools

import (
	"errors"
	"time"
)

// LogQuery reads the newest lines of the current log file.
type LogQuery struct {
	// Limit is the maximum number of lines (1-1000, default 200).
	Limit int `json:"limit,omitzero"`
	// Level is the minimum level: debug, info, warn or error.
	Level string `json:"level,omitzero"`
	// Contains keeps lines containing this text, case-insensitively.
	Contains string `json:"contains,omitzero"`
}

// RecentLogs is the result of a LogQuery, oldest line first.
type RecentLogs struct {
	Lines []string `json:"lines"`
	// Truncated reports that older matching lines were dropped by Limit.
	Truncated bool `json:"truncated"`
	// Partial reports that only the end of a large log file was searched.
	Partial bool `json:"partial"`
}

// ProfileTypes are the runtime profiles the profiler collects.
var ProfileTypes = []string{"cpu", "heap", "allocs", "goroutine", "mutex", "block"}

var (
	// ErrProfilingDisabled means runtime profiling is turned off in settings.
	ErrProfilingDisabled = errors.New("profiling is disabled; enable it in the general settings")
	// ErrProfilerBusy means a CPU profile or too many profiles are running.
	ErrProfilerBusy = errors.New("the profiler is busy")
	// ErrProfileNotFound means the session does not exist or has expired.
	ErrProfileNotFound = errors.New("profile session not found")
)

// ProfileRequest starts a profile. CPU profiles sample for Seconds (1-120);
// other profiles are snapshots, or deltas over Seconds when it is set.
type ProfileRequest struct {
	Type    string `json:"type"`
	Seconds int    `json:"seconds"`
}

// ProfileSession describes one collected or running profile.
type ProfileSession struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"`
	Seconds     int       `json:"seconds"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"createdAt"`
	CompletedAt time.Time `json:"completedAt"`
	Size        int       `json:"size"`
	Error       string    `json:"error,omitempty"`
}

// ProfileSessions lists the profiler's sessions.
type ProfileSessions struct {
	Enabled  bool             `json:"enabled"`
	Sessions []ProfileSession `json:"sessions"`
}

// ProfileAnalysisRequest summarizes a completed profile.
type ProfileAnalysisRequest struct {
	ID string `json:"id"`
	// SampleType selects a value such as cpu, inuse_space, alloc_space,
	// contentions or delay. Empty uses the profile's default.
	SampleType string `json:"sampleType,omitzero"`
	// Mode is functions (top functions by flat and cumulative value) or
	// stacks (top complete call stacks).
	Mode string `json:"mode,omitzero"`
	// Limit is the number of rows (1-200, default 25).
	Limit int `json:"limit,omitzero"`
	// Focus keeps samples whose stack contains a function name with this text.
	Focus string `json:"focus,omitzero"`
	// Wait waits for a running profile to finish (at most about two minutes).
	Wait bool `json:"wait,omitzero"`
}

// ProfileFunction is one row of a functions summary.
type ProfileFunction struct {
	Function          string  `json:"function"`
	File              string  `json:"file,omitempty"`
	Flat              int64   `json:"flat"`
	FlatPercent       float64 `json:"flatPercent"`
	Cumulative        int64   `json:"cumulative"`
	CumulativePercent float64 `json:"cumulativePercent"`
}

// ProfileStack is one row of a stacks summary, leaf first.
type ProfileStack struct {
	Value   int64    `json:"value"`
	Percent float64  `json:"percent"`
	Frames  []string `json:"frames"`
}

// ProfileAnalysis is a text-friendly summary of a profile.
type ProfileAnalysis struct {
	Session     ProfileSession    `json:"session"`
	SampleType  string            `json:"sampleType"`
	Unit        string            `json:"unit"`
	SampleTypes []string          `json:"sampleTypes"`
	Total       int64             `json:"total"`
	Duration    string            `json:"duration,omitempty"`
	Functions   []ProfileFunction `json:"functions,omitempty"`
	Stacks      []ProfileStack    `json:"stacks,omitempty"`
}

// RuntimeStats describes the running process.
type RuntimeStats struct {
	GoVersion     string  `json:"goVersion"`
	OS            string  `json:"os"`
	Arch          string  `json:"arch"`
	CPUs          int     `json:"cpus"`
	GOMAXPROCS    int     `json:"gomaxprocs"`
	Goroutines    int     `json:"goroutines"`
	UptimeSeconds int64   `json:"uptimeSeconds"`
	HeapAlloc     uint64  `json:"heapAllocBytes"`
	HeapInuse     uint64  `json:"heapInuseBytes"`
	HeapObjects   uint64  `json:"heapObjects"`
	StackInuse    uint64  `json:"stackInuseBytes"`
	Sys           uint64  `json:"sysBytes"`
	TotalAlloc    uint64  `json:"totalAllocBytes"`
	NextGC        uint64  `json:"nextGcBytes"`
	NumGC         uint32  `json:"numGc"`
	GCPauseTotal  string  `json:"gcPauseTotal"`
	LastGCPause   string  `json:"lastGcPause"`
	GCCPUFraction float64 `json:"gcCpuFraction"`
	Cgo           int64   `json:"cgoCalls"`
}
