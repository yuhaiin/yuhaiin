package app

import (
	"cmp"
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	contracttools "github.com/Asutorufa/yuhaiin/pkg/contract/tools"
	"github.com/google/pprof/profile"
)

// The profiler serves the management API operations as well as its HTTP
// routes, so MCP and other clients share the same sessions and limits.

func (p *profilerService) toSession(info profilerSessionInfo) contracttools.ProfileSession {
	return contracttools.ProfileSession{ID: info.ID, Type: info.Type, Seconds: info.Seconds, Status: info.Status, CreatedAt: info.CreatedAt, CompletedAt: info.CompletedAt, Size: info.Size, Error: info.Error}
}

func (p *profilerService) Sessions(context.Context) (contracttools.ProfileSessions, error) {
	out := contracttools.ProfileSessions{Enabled: pprofEnabled.Load(), Sessions: []contracttools.ProfileSession{}}
	for _, info := range p.list() {
		out.Sessions = append(out.Sessions, p.toSession(info))
	}
	return out, nil
}

func (p *profilerService) StartProfile(_ context.Context, request contracttools.ProfileRequest) (contracttools.ProfileSession, error) {
	info, status, err := p.start(request.Type, request.Seconds)
	switch {
	case err == nil:
		return p.toSession(info), nil
	case status == http.StatusForbidden:
		return contracttools.ProfileSession{}, contracttools.ErrProfilingDisabled
	case status == http.StatusConflict || status == http.StatusTooManyRequests:
		return contracttools.ProfileSession{}, errors.Join(contracttools.ErrProfilerBusy, err)
	default:
		return contracttools.ProfileSession{}, err
	}
}

func (p *profilerService) RemoveProfile(_ context.Context, id string) error {
	if !p.remove(id) {
		return contracttools.ErrProfileNotFound
	}
	return nil
}

// AnalyzeProfile summarizes a completed profile as its top functions or top
// call stacks, the text equivalent of pprof's top and traces views.
func (p *profilerService) AnalyzeProfile(ctx context.Context, request contracttools.ProfileAnalysisRequest) (contracttools.ProfileAnalysis, error) {
	session, info, ok := p.get(request.ID)
	if !ok {
		return contracttools.ProfileAnalysis{}, contracttools.ErrProfileNotFound
	}
	if info.Status == "running" && request.Wait {
		deadline := info.CreatedAt.Add(time.Duration(info.Seconds)*time.Second + 15*time.Second)
		for info.Status == "running" {
			if time.Now().After(deadline) {
				break
			}
			select {
			case <-ctx.Done():
				return contracttools.ProfileAnalysis{}, ctx.Err()
			case <-time.After(200 * time.Millisecond):
			}
			if session, info, ok = p.get(request.ID); !ok {
				return contracttools.ProfileAnalysis{}, contracttools.ErrProfileNotFound
			}
		}
	}
	out := contracttools.ProfileAnalysis{Session: p.toSession(info)}
	if info.Status != "completed" {
		if info.Status == "running" {
			return out, errors.New("the profile is still running; call again with wait or later")
		}
		return out, errors.New("the profile did not complete: " + cmp.Or(info.Error, info.Status))
	}
	parsed, err := profile.ParseData(session.raw)
	if err != nil {
		return out, err
	}
	return summarizeProfile(parsed, out, request)
}

func summarizeProfile(parsed *profile.Profile, out contracttools.ProfileAnalysis, request contracttools.ProfileAnalysisRequest) (contracttools.ProfileAnalysis, error) {
	if len(parsed.SampleType) == 0 {
		return out, errors.New("the profile has no sample values")
	}
	index := len(parsed.SampleType) - 1
	if parsed.DefaultSampleType != "" {
		for i, st := range parsed.SampleType {
			if st.Type == parsed.DefaultSampleType {
				index = i
			}
		}
	}
	for i, st := range parsed.SampleType {
		out.SampleTypes = append(out.SampleTypes, st.Type)
		if request.SampleType != "" && st.Type == request.SampleType {
			index = i
		}
	}
	if request.SampleType != "" && parsed.SampleType[index].Type != request.SampleType {
		return out, errors.New("unknown sample type; use one of: " + strings.Join(out.SampleTypes, ", "))
	}
	out.SampleType, out.Unit = parsed.SampleType[index].Type, parsed.SampleType[index].Unit
	if parsed.DurationNanos > 0 {
		out.Duration = time.Duration(parsed.DurationNanos).String()
	}
	focus := strings.ToLower(request.Focus)
	flat := map[string]int64{}
	cumulative := map[string]int64{}
	files := map[string]string{}
	stacks := map[string]*contracttools.ProfileStack{}
	for _, sample := range parsed.Sample {
		value := sample.Value[index]
		if value == 0 {
			continue
		}
		var frames []string
		for _, location := range sample.Location {
			// Line[0] is the innermost inlined function of the location.
			for _, line := range location.Line {
				if line.Function == nil {
					continue
				}
				frames = append(frames, line.Function.Name)
				if _, ok := files[line.Function.Name]; !ok {
					files[line.Function.Name] = line.Function.Filename
				}
			}
		}
		if len(frames) == 0 {
			frames = []string{"(unknown)"}
		}
		if focus != "" && !slices.ContainsFunc(frames, func(frame string) bool { return strings.Contains(strings.ToLower(frame), focus) }) {
			continue
		}
		out.Total += value
		flat[frames[0]] += value
		seen := map[string]bool{}
		for _, frame := range frames {
			if !seen[frame] {
				seen[frame] = true
				cumulative[frame] += value
			}
		}
		if request.Mode == "stacks" {
			if len(frames) > 32 {
				frames = append(frames[:32], "…")
			}
			key := strings.Join(frames, "\n")
			if stacks[key] == nil {
				stacks[key] = &contracttools.ProfileStack{Frames: frames}
			}
			stacks[key].Value += value
		}
	}
	percent := func(value int64) float64 {
		if out.Total == 0 {
			return 0
		}
		return float64(int64(float64(value)*10000/float64(out.Total))) / 100
	}
	if request.Mode == "stacks" {
		for _, stack := range stacks {
			stack.Percent = percent(stack.Value)
			out.Stacks = append(out.Stacks, *stack)
		}
		slices.SortFunc(out.Stacks, func(a, b contracttools.ProfileStack) int {
			return cmp.Or(cmp.Compare(b.Value, a.Value), strings.Compare(a.Frames[0], b.Frames[0]))
		})
		out.Stacks = out.Stacks[:min(len(out.Stacks), request.Limit)]
		return out, nil
	}
	for name, value := range cumulative {
		out.Functions = append(out.Functions, contracttools.ProfileFunction{Function: name, File: files[name], Flat: flat[name], FlatPercent: percent(flat[name]), Cumulative: value, CumulativePercent: percent(value)})
	}
	slices.SortFunc(out.Functions, func(a, b contracttools.ProfileFunction) int {
		return cmp.Or(cmp.Compare(b.Flat, a.Flat), cmp.Compare(b.Cumulative, a.Cumulative), strings.Compare(a.Function, b.Function))
	})
	out.Functions = out.Functions[:min(len(out.Functions), request.Limit)]
	return out, nil
}
