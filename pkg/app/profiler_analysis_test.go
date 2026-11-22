package app

import (
	"context"
	"errors"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"

	contracttools "github.com/Asutorufa/yuhaiin/pkg/contract/tools"
)

func busyAnalysisLoop(ctx context.Context) {
	x := 0
	for ctx.Err() == nil {
		for i := range 100000 {
			x ^= i * 31
		}
	}
	runtime.KeepAlive(x)
}

func parkedAnalysisGoroutine(ready *sync.WaitGroup, stop <-chan struct{}) {
	ready.Done()
	<-stop
}

func TestProfilerAnalysisSummarizesProfiles(t *testing.T) {
	setPprofEnabled(true)
	t.Cleanup(func() { setPprofEnabled(false) })
	p := newProfilerService()
	t.Cleanup(p.stop)
	ctx := t.Context()

	stop := make(chan struct{})
	var ready sync.WaitGroup
	for range 20 {
		ready.Add(1)
		go parkedAnalysisGoroutine(&ready, stop)
	}
	ready.Wait()
	defer close(stop)

	session, err := p.StartProfile(ctx, contracttools.ProfileRequest{Type: "goroutine"})
	if err != nil {
		t.Fatal(err)
	}
	analysis, err := p.AnalyzeProfile(ctx, contracttools.ProfileAnalysisRequest{ID: session.ID, Mode: "functions", Limit: 200, Wait: true})
	if err != nil {
		t.Fatal(err)
	}
	if analysis.Session.Status != "completed" || analysis.Total < 20 || analysis.SampleType != "goroutine" {
		t.Fatalf("analysis = %+v", analysis)
	}
	if !slices.ContainsFunc(analysis.Functions, func(f contracttools.ProfileFunction) bool {
		return strings.HasSuffix(f.Function, "parkedAnalysisGoroutine") && f.Cumulative >= 20 && f.CumulativePercent > 0
	}) {
		t.Fatalf("parked goroutines not found: %+v", analysis.Functions)
	}
	stacks, err := p.AnalyzeProfile(ctx, contracttools.ProfileAnalysisRequest{ID: session.ID, Mode: "stacks", Limit: 1, Focus: "parkedAnalysis", Wait: true})
	if err != nil || len(stacks.Stacks) != 1 || stacks.Stacks[0].Value < 20 || stacks.Total != stacks.Stacks[0].Value || !slices.ContainsFunc(stacks.Stacks[0].Frames, func(frame string) bool { return strings.Contains(frame, "parkedAnalysisGoroutine") }) {
		t.Fatalf("stacks = %+v %v", stacks, err)
	}
	if _, err := p.AnalyzeProfile(ctx, contracttools.ProfileAnalysisRequest{ID: session.ID, Mode: "functions", Limit: 5, SampleType: "bogus"}); err == nil {
		t.Fatal("unknown sample type accepted")
	}

	// A CPU profile finds the function that burns CPU.
	burn, cancel := context.WithCancel(ctx)
	defer cancel()
	go busyAnalysisLoop(burn)
	cpu, err := p.StartProfile(ctx, contracttools.ProfileRequest{Type: "cpu", Seconds: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.StartProfile(ctx, contracttools.ProfileRequest{Type: "cpu", Seconds: 1}); !errors.Is(err, contracttools.ErrProfilerBusy) {
		t.Fatalf("second CPU profile: %v", err)
	}
	analysis, err = p.AnalyzeProfile(ctx, contracttools.ProfileAnalysisRequest{ID: cpu.ID, Mode: "functions", Limit: 10, Wait: true})
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	if analysis.Unit != "nanoseconds" || analysis.Duration == "" || !slices.ContainsFunc(analysis.Functions, func(f contracttools.ProfileFunction) bool {
		return strings.HasSuffix(f.Function, "busyAnalysisLoop") && f.Flat > 0
	}) {
		t.Fatalf("cpu analysis = %+v", analysis)
	}

	sessions, _ := p.Sessions(ctx)
	if !sessions.Enabled || len(sessions.Sessions) != 2 {
		t.Fatalf("sessions = %+v", sessions)
	}
	if err := p.RemoveProfile(ctx, cpu.ID); err != nil {
		t.Fatal(err)
	}
	if err := p.RemoveProfile(ctx, cpu.ID); !errors.Is(err, contracttools.ErrProfileNotFound) {
		t.Fatal(err)
	}
	if _, err := p.AnalyzeProfile(ctx, contracttools.ProfileAnalysisRequest{ID: "missing", Mode: "functions", Limit: 1}); !errors.Is(err, contracttools.ErrProfileNotFound) {
		t.Fatal(err)
	}

	setPprofEnabled(false)
	if _, err := p.StartProfile(ctx, contracttools.ProfileRequest{Type: "heap"}); !errors.Is(err, contracttools.ErrProfilingDisabled) {
		t.Fatalf("disabled profiling: %v", err)
	}
}
