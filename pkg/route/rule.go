package route

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	contractconnection "github.com/Asutorufa/yuhaiin/pkg/contract/connection"
	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
)

type Rules struct {
	rules    RouteRuleBook
	settings RouteSettingsBook
	route    *Route

	applyTimer   *time.Timer
	applyTimerMu sync.Mutex
	applyAt      atomic.Int64
	applyVersion atomic.Uint64
	applyMu      sync.Mutex
	applyError   atomic.Pointer[string]
	closed       atomic.Bool
	applying     atomic.Bool
}

type RouteRuleBook interface {
	ListRules(context.Context) ([]plainstore.RouteRuleEntry, error)
}

type RouteSettingsBook interface {
	Settings(context.Context) (plainstore.RouteSettings, error)
}

func NewRules(rules RouteRuleBook, settings RouteSettingsBook, route *Route) *Rules {
	r := &Rules{
		rules:    rules,
		settings: settings,
		route:    route,
	}

	route.ms.list.applyCoordinator.Store(new(r.Apply))
	route.ms.list.scheduleCoordinator.Store(new(r.ScheduleApply))
	if book, ok := rules.(interface{ ResetActivation(context.Context) error }); ok {
		if err := book.ResetActivation(context.Background()); err != nil {
			r.applyError.Store(new(err.Error()))
			return r
		}
	}
	r.ApplyStored(context.Background())
	return r
}

func (r *Rules) ApplyStored(ctx context.Context) {
	_ = r.applyStored(ctx)
}

func (r *Rules) applyStored(ctx context.Context) (err error) {
	if r == nil {
		return nil
	}
	r.applyMu.Lock()
	defer r.applyMu.Unlock()
	if r.closed.Load() {
		return errors.New("route runtime is closed")
	}
	r.applying.Store(true)
	defer r.applying.Store(false)
	defer func() {
		message := ""
		if err != nil {
			message = err.Error()
		}
		r.applyError.Store(new(message))
	}()
	if book, ok := r.rules.(interface {
		Snapshot(context.Context) (plainstore.RouteSnapshot, error)
		ActivateSnapshot(context.Context, uint64, func()) error
	}); ok {
		r.route.ms.list.contentMu.Lock()
		defer r.route.ms.list.contentMu.Unlock()
		for range 4 {
			snapshot, err := book.Snapshot(ctx)
			if err != nil {
				return err
			}
			config := routeConfigFromStore(snapshot.Settings)
			config.Generation = snapshot.Revision
			err = r.route.ms.UpdateSnapshot(ctx, snapshot, book.ActivateSnapshot, config, func() { r.route.config.Store(config) })
			if errors.Is(err, plainstore.ErrConflict) {
				continue
			}
			if err != nil {
				return err
			}
			r.route.ms.list.resetRefreshInterval(snapshot.ListSettings.RefreshInterval)
			return nil
		}
		return plainstore.ErrConflict
	}
	// Read settings before installing any rules or indexes. A failed settings
	// read must leave the whole running configuration untouched.
	var config *RouteConfig
	if r.settings != nil {
		settings, err := r.settings.Settings(ctx)
		if err != nil {
			return err
		}
		config = routeConfigFromStore(settings)
	}
	if r.rules != nil {
		entries, err := r.rules.ListRules(ctx)
		if err != nil {
			return err
		}
		routes := make([]contractroute.RouteRule, 0, len(entries))
		for _, entry := range entries {
			routes = append(routes, entry.Rule)
		}
		if err := r.route.ms.UpdateContext(ctx, routes...); err != nil {
			return err
		}
	}
	if config != nil {
		r.route.config.Store(config)
	}
	return nil
}

func (r *Rules) ScheduleApply() {
	if r == nil || r.closed.Load() {
		return
	}
	version := r.applyVersion.Add(1)
	r.applyAt.Store(time.Now().Add(time.Minute).UnixMilli())
	r.applyTimerMu.Lock()
	if r.closed.Load() {
		r.applyTimerMu.Unlock()
		return
	}
	if r.applyTimer != nil {
		r.applyTimer.Stop()
	}
	r.applyTimer = time.AfterFunc(time.Minute, func() { r.applyScheduled(version) })
	r.applyTimerMu.Unlock()
}

func (r *Rules) applyScheduled(version uint64) {
	if r.closed.Load() || r.applyVersion.Load() != version {
		return
	}
	if err := r.applyStored(context.Background()); err == nil && r.applyVersion.Load() == version {
		r.applyAt.Store(0)
	}
}

func (r *Rules) Apply(ctx context.Context) error {
	if r == nil {
		return nil
	}
	if r.closed.Load() {
		return errors.New("route runtime is closed")
	}
	version := r.applyVersion.Add(1)
	r.applyTimerMu.Lock()
	if r.applyTimer != nil {
		r.applyTimer.Stop()
	}
	r.applyTimerMu.Unlock()
	if err := r.applyStored(ctx); err != nil {
		return err
	}
	if r.applyVersion.Load() == version {
		r.applyAt.Store(0)
	}
	return nil
}

func (r *Rules) Close() error {
	r.closed.Store(true)
	r.applyVersion.Add(1)
	r.applyTimerMu.Lock()
	if r.applyTimer != nil {
		r.applyTimer.Stop()
	}
	r.applyTimerMu.Unlock()
	r.applyMu.Lock()
	r.applyAt.Store(0)
	r.applyMu.Unlock()
	return nil
}

func (r *Rules) ActivationStatus(ctx context.Context) (contractroute.RuleActivationStatus, error) {
	var config *RouteConfig
	if r.route != nil && r.route.config != nil {
		config = r.route.config.Load()
	}
	status := contractroute.RuleActivationStatus{ApplyAt: r.applyAt.Load(), Applying: r.applying.Load()}
	if r.route != nil && r.route.ms != nil {
		r.route.ms.mu.RLock()
		status.ListIssues = slices.Clone(r.route.ms.listIssues)
		status.SkippedRules = slices.Clone(r.route.ms.skippedRules)
		status.DegradedRules = slices.Clone(r.route.ms.degradedRules)
		r.route.ms.mu.RUnlock()
	}
	if config != nil {
		status.AppliedRevision = config.Generation
		mode := config.DefaultMode
		if mode == "" {
			mode = "proxy"
		}
		target := config.DefaultTarget
		if target.Type == "" {
			target.Type = "default"
		}
		status.RunningConfig = &contractroute.Config{Revision: config.Revision, DefaultMode: mode, DefaultTarget: target, DirectResolver: config.DirectResolver, ProxyResolver: config.ProxyResolver, ResolveLocally: config.ResolveLocally, UdpProxyFqdnStrategy: string(config.UDPProxyFQDNStrategy)}
	}
	if book, ok := r.rules.(interface {
		ConfigurationRevision(context.Context) (uint64, error)
	}); ok {
		revision, err := book.ConfigurationRevision(ctx)
		if err != nil {
			return status, err
		}
		status.SavedRevision = revision
	}
	if message := r.applyError.Load(); message != nil {
		status.Error = *message
	}
	return status, nil
}

func routeConfigFromStore(settings plainstore.RouteSettings) *RouteConfig {
	return &RouteConfig{
		Revision:             settings.Revision,
		DefaultMode:          settings.DefaultMode,
		DefaultTarget:        settings.DefaultTarget,
		DirectResolver:       settings.DirectResolver,
		ProxyResolver:        settings.ProxyResolver,
		ResolveLocally:       settings.ResolveLocally,
		UDPProxyFQDNStrategy: udpProxyFQDNStrategyFromCode(settings.UDPProxyFQDN),
	}
}

func udpProxyFQDNStrategyFromCode(value int) UDPProxyFQDNStrategy {
	switch value {
	case 1:
		return UDPProxyFQDNResolve
	case 2:
		return UDPProxyFQDNSkipResolve
	default:
		return UDPProxyFQDNDefault
	}
}

func (r *Rules) TestContract(ctx context.Context, host string) (contractroute.RuleTestResponse, error) {
	ctx, store := netapi.GetOrNewContext(ctx)

	var addr netapi.Address
	hostname, portstr, err := net.SplitHostPort(host)
	if err == nil {
		port, er := strconv.ParseUint(portstr, 10, 16)
		if er != nil {
			return contractroute.RuleTestResponse{}, fmt.Errorf("parse port failed: %w", er)
		}
		addr, err = netapi.ParseAddressPort("tcp", hostname, uint16(port))
	} else {
		addr, err = netapi.ParseAddressPort("tcp", host, 0)
	}
	if err != nil {
		return contractroute.RuleTestResponse{}, fmt.Errorf("parse addr failed: %w", err)
	}

	result := r.route.dispatch(ctx, addr)
	ips, _ := store.ConnOptions().RouteIPs(ctx, addr)

	out := contractroute.RuleTestResponse{
		Mode:        result.Mode.Mode().String(),
		Target:      result.Mode.Target(),
		Resolver:    result.Mode.Resolver(),
		AfterAddr:   result.Addr.String(),
		Lists:       store.ConnOptions().Lists(),
		ListNames:   store.ConnOptions().MatchedListNames(),
		MatchResult: contractMatchHistory(store.MatchHistory()),
	}
	if ips != nil {
		for ip := range ips.Iter() {
			out.IPs = append(out.IPs, ip.String())
		}
	}
	return out, nil
}

func (r *Rules) BlockHistoryContract(ctx context.Context) (contractroute.BlockHistoryList, error) {
	return r.route.Get(), nil
}

func contractMatchHistory(entry []contractconnection.MatchHistoryEntry) []contractroute.MatchHistoryEntry {
	out := make([]contractroute.MatchHistoryEntry, 0, len(entry))
	for _, e := range entry {
		history := make([]contractroute.MatchResult, 0, len(e.History))
		for _, result := range e.History {
			history = append(history, contractroute.MatchResult{
				Kind: result.Kind, ID: result.ID,
				ListName: result.ListName,
				Matched:  result.Matched,
			})
		}
		out = append(out, contractroute.MatchHistoryEntry{
			RuleID:   e.RuleID,
			RuleName: e.RuleName,
			History:  history,
			Trace:    contractMatchTrace(contractconnection.ReconstructMatchTrace(e.TraceTemplate, e.History)),
		})
	}
	return out
}

func InsertBefore[T any](s []T, from, to int) []T {
	result := make([]T, 0, len(s))
	elem := s[from]
	for index, v := range s {
		if index == from {
			continue
		}
		if index == to {
			result = append(result, elem)
		}
		result = append(result, v)
	}
	return result
}

func InsertAfter[T any](s []T, from, to int) []T {
	result := make([]T, 0, len(s))
	elem := s[from]
	for index, v := range s {
		if index == from {
			continue
		}
		result = append(result, v)
		if index == to {
			result = append(result, elem)
		}
	}
	return result
}

func contractMatchTrace(trace *contractconnection.MatchTrace) *contractroute.MatchTrace {
	if trace == nil {
		return nil
	}
	out := &contractroute.MatchTrace{
		Type: trace.Type, Label: trace.Label, State: trace.State,
		Kind: trace.Kind, ID: trace.ID,
	}
	for i := range trace.Children {
		if child := contractMatchTrace(&trace.Children[i]); child != nil {
			out.Children = append(out.Children, *child)
		}
	}
	return out
}
