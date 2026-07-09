package route

import (
	"context"
	"fmt"
	"net"
	"strconv"

	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
)

type Rules struct {
	rules    RouteRuleBook
	settings RouteSettingsBook
	route    *Route
}

type RouteRuleBook interface {
	ListRules(context.Context) ([]plainstore.RouteRuleEntry, error)
}

type RouteSettingsBook interface {
	Settings(context.Context) (plainstore.RouteSettings, error)
	SaveSettings(context.Context, plainstore.RouteSettings) error
}

func NewRules(rules RouteRuleBook, settings RouteSettingsBook, route *Route) *Rules {
	r := &Rules{
		rules:    rules,
		settings: settings,
		route:    route,
	}

	r.ApplyStored(context.Background())
	return r
}

func (r *Rules) ApplyStored(ctx context.Context) {
	if r == nil {
		return
	}
	if r.rules != nil {
		entries, err := r.rules.ListRules(ctx)
		if err == nil {
			routes := make([]contractroute.RouteRule, 0, len(entries))
			for _, entry := range entries {
				routes = append(routes, entry.Rule)
			}
			r.route.ms.Update(routes...)
		}
	}
	if r.settings != nil {
		settings, err := r.settings.Settings(ctx)
		if err == nil {
			r.route.config.Store(routeConfigFromStore(settings))
		}
	}
}

func (r *Rules) SaveContractConfig(ctx context.Context, req contractroute.Config) error {
	settings := routeSettingsFromContract(req)
	if r.settings != nil {
		if err := r.settings.SaveSettings(ctx, settings); err != nil {
			return err
		}
	}
	r.route.config.Store(routeConfigFromStore(settings))
	return nil
}

func routeSettingsFromContract(req contractroute.Config) plainstore.RouteSettings {
	return plainstore.RouteSettings{
		DirectResolver: req.DirectResolver,
		ProxyResolver:  req.ProxyResolver,
		ResolveLocally: req.ResolveLocally,
		UDPProxyFQDN:   udpProxyFQDNStrategyCode(req.UdpProxyFqdnStrategy),
	}
}

func routeConfigFromStore(settings plainstore.RouteSettings) *RouteConfig {
	return &RouteConfig{
		DirectResolver:       settings.DirectResolver,
		ProxyResolver:        settings.ProxyResolver,
		ResolveLocally:       settings.ResolveLocally,
		UDPProxyFQDNStrategy: udpProxyFQDNStrategyFromCode(settings.UDPProxyFQDN),
	}
}

func udpProxyFQDNStrategyCode(value string) int {
	switch parseUDPProxyFQDNStrategy(value) {
	case UDPProxyFQDNResolve:
		return 1
	case UDPProxyFQDNSkipResolve:
		return 2
	default:
		return 0
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
	var addr netapi.Address
	hostname, portstr, err := net.SplitHostPort(host)
	if err == nil {
		port, er := strconv.ParseUint(portstr, 10, 16)
		if er != nil {
			return contractroute.RuleTestResponse{}, fmt.Errorf("parse port failed: %w", er)
		}
		addr, err = netapi.ParseAddressPort(hostname, hostname, uint16(port))
	} else {
		addr, err = netapi.ParseAddressPort("", host, 0)
	}
	if err != nil {
		return contractroute.RuleTestResponse{}, fmt.Errorf("parse addr failed: %w", err)
	}

	store := netapi.GetContext(ctx)
	result := r.route.dispatch(ctx, addr)
	ips, _ := store.ConnOptions().RouteIPs(ctx, addr)

	out := contractroute.RuleTestResponse{
		Mode:        result.Mode.Mode().String(),
		Tag:         result.Mode.GetTag(),
		Resolver:    result.Mode.Resolver(),
		AfterAddr:   result.Addr.String(),
		Lists:       store.ConnOptions().Lists(),
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

func contractMatchHistory(entry []*netapi.MatchHistoryEntry) []contractroute.MatchHistoryEntry {
	out := make([]contractroute.MatchHistoryEntry, 0, len(entry))
	for _, e := range entry {
		if e == nil {
			continue
		}
		history := make([]contractroute.MatchResult, 0, len(e.UnmatchedHistory)+1)
		for _, uh := range e.UnmatchedHistory {
			history = append(history, contractroute.MatchResult{ListName: uh.Value()})
		}
		if m := e.MatchedHistory.Value(); m != "" {
			history = append(history, contractroute.MatchResult{ListName: m, Matched: true})
		}
		out = append(out, contractroute.MatchHistoryEntry{
			RuleName: e.RuleName.Value(),
			History:  history,
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
