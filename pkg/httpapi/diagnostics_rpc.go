package httpapi

import (
	"context"
	"errors"

	"runtime"
	"strings"
	"time"

	contracttools "github.com/Asutorufa/yuhaiin/pkg/contract/tools"
	"github.com/Asutorufa/yuhaiin/pkg/security/secret"
)

// ProfilerController collects runtime profiles and summarizes them.
type ProfilerController interface {
	Sessions(context.Context) (contracttools.ProfileSessions, error)
	StartProfile(context.Context, contracttools.ProfileRequest) (contracttools.ProfileSession, error)
	RemoveProfile(context.Context, string) error
	AnalyzeProfile(context.Context, contracttools.ProfileAnalysisRequest) (contracttools.ProfileAnalysis, error)
}

// LogReader is the optional bounded log reader of a ToolsController.
type LogReader interface {
	RecentLogs(context.Context, contracttools.LogQuery) (contracttools.RecentLogs, error)
}

var processStart = time.Now()

func addDiagnosticRPCRoutes(handlers *v2Handlers, services V2Services) {
	api := v2API{services: services}
	addRPCRoute(handlers, v2LogsRecent, api.recentLogs)
	addRPCRoute(handlers, v2RuntimeStats, api.runtimeStats)
	addRPCRoute(handlers, v2ProfilerSessions, api.profilerSessions)
	addRPCRoute(handlers, v2ProfilerStart, api.startProfile)
	addRPCRoute(handlers, v2ProfilerDelete, api.deleteProfile)
	addRPCRoute(handlers, v2ProfilerAnalyze, api.analyzeProfile)
}

func (a v2API) recentLogs(ctx context.Context, request *contracttools.LogQuery) (*contracttools.RecentLogs, error) {
	reader, ok := a.services.Tools.(LogReader)
	if !ok {
		return nil, unavailable("log reader is unavailable")
	}
	if request.Limit == 0 {
		request.Limit = 200
	}
	if request.Limit < 1 || request.Limit > 1000 || len(request.Contains) > 256 {
		return nil, badRequest(errors.New("limit must be between 1 and 1000 and contains at most 256 characters"))
	}
	if level := strings.ToLower(request.Level); level != "" && level != "debug" && level != "info" && level != "warn" && level != "warning" && level != "error" {
		return nil, badRequest(errors.New("level must be debug, info, warn or error"))
	}
	// Logs can contain credentials that redaction cannot find, so they are
	// raw secret data: secrets:read is checked and the read audited here, in
	// the operation, for every transport.
	if err := secret.AuthorizeRetrieval(ctx, "logs.recent"); err != nil {
		return nil, err
	}
	return pointer(reader.RecentLogs(ctx, *request))
}

func (a v2API) runtimeStats(context.Context, *emptyRequest) (*contracttools.RuntimeStats, error) {
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	lastPause := time.Duration(0)
	if memory.NumGC > 0 {
		lastPause = time.Duration(memory.PauseNs[(memory.NumGC+255)%256])
	}
	return &contracttools.RuntimeStats{
		GoVersion: runtime.Version(), OS: runtime.GOOS, Arch: runtime.GOARCH, CPUs: runtime.NumCPU(), GOMAXPROCS: runtime.GOMAXPROCS(0),
		Goroutines: runtime.NumGoroutine(), UptimeSeconds: int64(time.Since(processStart).Seconds()),
		HeapAlloc: memory.HeapAlloc, HeapInuse: memory.HeapInuse, HeapObjects: memory.HeapObjects, StackInuse: memory.StackInuse,
		Sys: memory.Sys, TotalAlloc: memory.TotalAlloc, NextGC: memory.NextGC, NumGC: memory.NumGC,
		GCPauseTotal: time.Duration(memory.PauseTotalNs).String(), LastGCPause: lastPause.String(), GCCPUFraction: memory.GCCPUFraction,
		Cgo: runtime.NumCgoCall(),
	}, nil
}

func (a v2API) profiler() (ProfilerController, error) {
	if a.services.Profiler == nil {
		return nil, unavailable("profiler is unavailable")
	}
	return a.services.Profiler, nil
}

func profilerError(err error) error {
	switch {
	case errors.Is(err, contracttools.ErrProfilingDisabled):
		return &rpcError{status: 409, code: "profiling_disabled", message: err.Error()}
	case errors.Is(err, contracttools.ErrProfilerBusy):
		return &rpcError{status: 409, code: "conflict", message: err.Error()}
	case errors.Is(err, contracttools.ErrProfileNotFound):
		return notFound(err)
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	default:
		return badRequest(err)
	}
}

func (a v2API) profilerSessions(ctx context.Context, _ *emptyRequest) (*contracttools.ProfileSessions, error) {
	p, err := a.profiler()
	if err != nil {
		return nil, err
	}
	return pointer(p.Sessions(ctx))
}

func (a v2API) startProfile(ctx context.Context, request *contracttools.ProfileRequest) (*contracttools.ProfileSession, error) {
	p, err := a.profiler()
	if err != nil {
		return nil, err
	}
	session, err := p.StartProfile(ctx, *request)
	if err != nil {
		return nil, profilerError(err)
	}
	return &session, nil
}

func (a v2API) deleteProfile(ctx context.Context, request *idRequest) (*emptyResponse, error) {
	p, err := a.profiler()
	if err != nil {
		return nil, err
	}
	if err := p.RemoveProfile(ctx, request.ID); err != nil {
		return nil, profilerError(err)
	}
	return &emptyResponse{}, nil
}

func (a v2API) analyzeProfile(ctx context.Context, request *contracttools.ProfileAnalysisRequest) (*contracttools.ProfileAnalysis, error) {
	p, err := a.profiler()
	if err != nil {
		return nil, err
	}
	if request.Limit == 0 {
		request.Limit = 25
	}
	if request.Limit < 1 || request.Limit > 200 || len(request.Focus) > 256 || len(request.SampleType) > 64 {
		return nil, badRequest(errors.New("limit must be between 1 and 200; focus and sampleType must be short"))
	}
	if request.Mode == "" {
		request.Mode = "functions"
	}
	if request.Mode != "functions" && request.Mode != "stacks" {
		return nil, badRequest(errors.New("mode must be functions or stacks"))
	}
	analysis, err := p.AnalyzeProfile(ctx, *request)
	if err != nil {
		return nil, profilerError(err)
	}
	return &analysis, nil
}
