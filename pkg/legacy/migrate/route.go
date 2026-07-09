package migrate

import (
	"fmt"

	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
	schemaapi "github.com/Asutorufa/yuhaiin/pkg/legacy/schema/api"
	schemaconfig "github.com/Asutorufa/yuhaiin/pkg/legacy/schema/config"
	schemastatistic "github.com/Asutorufa/yuhaiin/pkg/legacy/schema/statistic"
)

func ConvertLegacyRuleList(in *schemaapi.RuleResponse) contractroute.RuleList {
	out := contractroute.RuleList{}
	if in == nil {
		return out
	}
	out.Items = make([]contractroute.RuleItem, 0, len(in.GetItems()))
	for _, item := range in.GetItems() {
		if item == nil {
			continue
		}
		out.Items = append(out.Items, contractroute.RuleItem{
			Name:      item.Name,
			Disabled:  item.Disabled,
			Index:     item.Index,
			Mode:      item.Mode,
			Tag:       item.Tag,
			Resolver:  item.Resolver,
			RuleCount: item.RuleCount,
		})
	}
	out.Page = convertPage(in.Page, len(out.Items))
	return out
}

func ConvertLegacyRouteList(in *schemaapi.ListResponse) contractroute.RouteList {
	out := contractroute.RouteList{}
	if in == nil {
		return out
	}
	out.Items = make([]contractroute.ListItem, 0, len(in.GetItems()))
	for _, item := range in.GetItems() {
		if item == nil {
			continue
		}
		out.Items = append(out.Items, contractroute.ListItem{
			Name:       item.Name,
			Type:       item.Type,
			Source:     item.Source,
			ItemCount:  item.ItemCount,
			ErrorCount: item.ErrorCount,
			Preview:    item.Preview,
		})
	}
	out.Page = convertPage(in.Page, len(out.Items))
	return out
}

func ConvertLegacyRule(in *schemaconfig.Rulev2) contractroute.RouteRule {
	if in == nil {
		return contractroute.RouteRule{Mode: "bypass"}
	}
	out := contractroute.RouteRule{
		Name:                 in.GetName(),
		Mode:                 in.GetMode().String(),
		Tag:                  in.GetTag(),
		ResolveStrategy:      in.GetResolveStrategy().String(),
		UdpProxyFqdnStrategy: in.GetUdpProxyFqdnStrategy().String(),
		Resolver:             in.GetResolver(),
		Disabled:             in.GetDisabled(),
	}
	out.Rules = make([]contractroute.RuleExpr, 0, len(in.GetRules()))
	for _, group := range in.GetRules() {
		if group == nil {
			continue
		}
		all := make([]contractroute.RuleExpr, 0, len(group.GetRules()))
		for _, rule := range group.GetRules() {
			if expr, ok := convertLegacyRuleExpr(rule); ok {
				all = append(all, expr)
			}
		}
		out.Rules = append(out.Rules, contractroute.RuleExpr{Type: "all", All: all})
	}
	return out
}

func ConvertContractRule(in contractroute.RouteRule) (*schemaconfig.Rulev2, error) {
	out := &schemaconfig.Rulev2{
		Name:                 in.Name,
		Mode:                 parseMode(in.Mode),
		Tag:                  in.Tag,
		ResolveStrategy:      parseResolveStrategy(in.ResolveStrategy),
		UdpProxyFqdnStrategy: parseUDPProxyFQDNStrategy(in.UdpProxyFqdnStrategy),
		Resolver:             in.Resolver,
		Disabled:             in.Disabled,
	}
	for i, expr := range in.Rules {
		group, err := convertContractRuleGroup(expr)
		if err != nil {
			return nil, fmt.Errorf("rules[%d]: %w", i, err)
		}
		out.Rules = append(out.Rules, group)
	}
	return out, nil
}

func ConvertLegacyListDetail(in *schemaconfig.List) contractroute.RouteListDetail {
	if in == nil {
		return contractroute.RouteListDetail{Type: "host", Source: contractroute.ListSource{Type: "local", Local: &contractroute.LocalSource{}}}
	}
	out := contractroute.RouteListDetail{
		Name:      in.GetName(),
		Type:      in.GetListType().String(),
		ErrorMsgs: append([]string(nil), in.GetErrorMsgs()...),
	}
	switch in.WhichList() {
	case schemaconfig.List_Remote_case:
		out.Source = contractroute.ListSource{
			Type:   "remote",
			Remote: &contractroute.RemoteSource{URLs: append([]string(nil), in.GetRemote().GetUrls()...)},
		}
	default:
		out.Source = contractroute.ListSource{
			Type:  "local",
			Local: &contractroute.LocalSource{Lists: append([]string(nil), in.GetLocal().GetLists()...)},
		}
	}
	return out
}

func ConvertContractListDetail(in contractroute.RouteListDetail) (*schemaconfig.List, error) {
	out := &schemaconfig.List{
		Name:      in.Name,
		ListType:  parseListType(in.Type),
		ErrorMsgs: append([]string(nil), in.ErrorMsgs...),
	}
	switch in.Source.Type {
	case "remote":
		var urls []string
		if in.Source.Remote != nil {
			urls = append([]string(nil), in.Source.Remote.URLs...)
		}
		out.Remote = &schemaconfig.ListRemote{Urls: urls}
	default:
		var lists []string
		if in.Source.Local != nil {
			lists = append([]string(nil), in.Source.Local.Lists...)
		}
		out.Local = &schemaconfig.ListLocal{Lists: lists}
	}
	return out, nil
}

func ConvertLegacyTagList(in *schemaapi.TagsResponse) contractroute.TagList {
	out := contractroute.TagList{}
	if in == nil {
		return out
	}
	out.Items = make([]contractroute.TagItem, 0, len(in.Items))
	for _, item := range in.Items {
		if item == nil || item.Tag == nil {
			continue
		}
		out.Items = append(out.Items, contractroute.TagItem{
			Name: item.Name,
			Type: item.Tag.GetType().String(),
			Hash: item.Tag.GetHash(),
		})
	}
	out.Page = contractroute.Page{Page: 1, PageSize: len(out.Items), Total: len(out.Items)}
	if in.Page != nil {
		out.Page = contractroute.Page{
			Page:     int(in.Page.Page),
			PageSize: int(in.Page.PageSize),
			Total:    int(in.Page.Total),
		}
	}
	return out
}

func convertLegacyRuleExpr(in *schemaconfig.Rule) (contractroute.RuleExpr, bool) {
	if in == nil {
		return contractroute.RuleExpr{}, false
	}
	switch in.WhichObject() {
	case schemaconfig.Rule_Host_case:
		return contractroute.RuleExpr{Type: "host", Host: &contractroute.ListRef{List: in.GetHost().GetList()}}, true
	case schemaconfig.Rule_Process_case:
		return contractroute.RuleExpr{Type: "process", Process: &contractroute.ListRef{List: in.GetProcess().GetList()}}, true
	case schemaconfig.Rule_Inbound_case:
		return contractroute.RuleExpr{Type: "inbound", Inbound: &contractroute.SourceRef{Name: in.GetInbound().GetName(), Names: append([]string(nil), in.GetInbound().GetNames()...)}}, true
	case schemaconfig.Rule_Network_case:
		return contractroute.RuleExpr{Type: "network", Network: &contractroute.NetworkExpr{Network: in.GetNetwork().GetNetwork().String()}}, true
	case schemaconfig.Rule_Port_case:
		return contractroute.RuleExpr{Type: "port", Port: &contractroute.PortExpr{Ports: in.GetPort().GetPorts()}}, true
	case schemaconfig.Rule_Geoip_case:
		return contractroute.RuleExpr{Type: "geoip", GeoIP: &contractroute.GeoIPExpr{Countries: in.GetGeoip().GetCountries()}}, true
	default:
		return contractroute.RuleExpr{}, false
	}
}

func convertContractRuleGroup(expr contractroute.RuleExpr) (*schemaconfig.Or, error) {
	if expr.Type == "" {
		expr.Type = "all"
	}
	switch expr.Type {
	case "all":
		group := &schemaconfig.Or{}
		for i, child := range expr.All {
			rule, err := convertContractLeafRule(child)
			if err != nil {
				return nil, fmt.Errorf("all[%d]: %w", i, err)
			}
			group.Rules = append(group.Rules, rule)
		}
		return group, nil
	default:
		rule, err := convertContractLeafRule(expr)
		if err != nil {
			return nil, err
		}
		return &schemaconfig.Or{Rules: []*schemaconfig.Rule{rule}}, nil
	}
}

func convertContractLeafRule(expr contractroute.RuleExpr) (*schemaconfig.Rule, error) {
	switch expr.Type {
	case "host":
		if expr.Host == nil {
			return nil, fmt.Errorf("host is empty")
		}
		return &schemaconfig.Rule{Host: &schemaconfig.Host{List: expr.Host.List}}, nil
	case "process":
		if expr.Process == nil {
			return nil, fmt.Errorf("process is empty")
		}
		return &schemaconfig.Rule{Process: &schemaconfig.Process{List: expr.Process.List}}, nil
	case "inbound":
		if expr.Inbound == nil {
			return nil, fmt.Errorf("inbound is empty")
		}
		return &schemaconfig.Rule{Inbound: &schemaconfig.Source{Name: expr.Inbound.Name, Names: append([]string(nil), expr.Inbound.Names...)}}, nil
	case "network":
		if expr.Network == nil {
			return nil, fmt.Errorf("network is empty")
		}
		return &schemaconfig.Rule{Network: &schemaconfig.Network{Network: parseNetwork(expr.Network.Network)}}, nil
	case "port":
		if expr.Port == nil {
			return nil, fmt.Errorf("port is empty")
		}
		return &schemaconfig.Rule{Port: &schemaconfig.Port{Ports: expr.Port.Ports}}, nil
	case "geoip":
		if expr.GeoIP == nil {
			return nil, fmt.Errorf("geoip is empty")
		}
		return &schemaconfig.Rule{Geoip: &schemaconfig.Geoip{Countries: expr.GeoIP.Countries}}, nil
	default:
		return nil, fmt.Errorf("unsupported rule expr type %q", expr.Type)
	}
}

func parseMode(value string) schemaconfig.Mode {
	if value == "" {
		return schemaconfig.Mode_bypass
	}
	if v, ok := schemaconfig.Mode_value[value]; ok {
		return schemaconfig.Mode(v)
	}
	return schemaconfig.Mode_bypass
}

func parseResolveStrategy(value string) schemaconfig.ResolveStrategy {
	if value == "" {
		return schemaconfig.ResolveStrategy_default
	}
	if v, ok := schemaconfig.ResolveStrategy_value[value]; ok {
		return schemaconfig.ResolveStrategy(v)
	}
	return schemaconfig.ResolveStrategy_default
}

func parseUDPProxyFQDNStrategy(value string) schemaconfig.UdpProxyFqdnStrategy {
	if value == "" {
		return schemaconfig.UdpProxyFqdnStrategy_udp_proxy_fqdn_strategy_default
	}
	if v, ok := schemaconfig.UdpProxyFqdnStrategy_value[value]; ok {
		return schemaconfig.UdpProxyFqdnStrategy(v)
	}
	return schemaconfig.UdpProxyFqdnStrategy_udp_proxy_fqdn_strategy_default
}

func parseNetwork(value string) schemaconfig.NetworkNetworkType {
	if v, ok := schemaconfig.NetworkNetworkType_value[value]; ok {
		return schemaconfig.NetworkNetworkType(v)
	}
	return schemaconfig.Network_unknown
}

func parseListType(value string) schemaconfig.ListListTypeEnum {
	if v, ok := schemaconfig.ListListTypeEnum_value[value]; ok {
		return schemaconfig.ListListTypeEnum(v)
	}
	return schemaconfig.List_host
}

func ConvertLegacyRuleTest(in *schemaapi.TestResponse) contractroute.RuleTestResponse {
	var out contractroute.RuleTestResponse
	if in == nil {
		return out
	}
	if in.Mode != nil {
		out.Mode = in.Mode.GetMode().String()
		out.Tag = in.Mode.GetTag()
		out.Resolver = in.Mode.GetResolver()
	}
	out.AfterAddr = in.AfterAddr
	out.Lists = in.Lists
	out.IPs = in.Ips
	out.MatchResult = convertRouteMatchHistory(in.MatchResult)
	return out
}

func ConvertLegacyBlockHistory(in *schemaapi.BlockHistoryList) contractroute.BlockHistoryList {
	var out contractroute.BlockHistoryList
	if in == nil {
		return out
	}
	out.DumpProcessEnabled = in.DumpProcessEnabled
	out.Items = make([]contractroute.BlockHistory, 0, len(in.Objects))
	for _, item := range in.Objects {
		if item == nil {
			continue
		}
		out.Items = append(out.Items, contractroute.BlockHistory{
			Protocol:   item.Protocol,
			Host:       item.Host,
			Time:       item.Time,
			Process:    item.Process,
			BlockCount: formatUint64(item.BlockCount),
		})
	}
	return out
}

func convertPage(page *schemaapi.PageResponse, fallbackTotal int) contractroute.Page {
	if page == nil {
		return contractroute.Page{Page: 1, PageSize: fallbackTotal, Total: fallbackTotal}
	}
	return contractroute.Page{
		Page:     int(page.Page),
		PageSize: int(page.PageSize),
		Total:    int(page.Total),
	}
}

func convertRouteMatchHistory(in []*schemastatistic.MatchHistoryEntry) []contractroute.MatchHistoryEntry {
	out := make([]contractroute.MatchHistoryEntry, 0, len(in))
	for _, entry := range in {
		if entry == nil {
			continue
		}
		history := make([]contractroute.MatchResult, 0, len(entry.GetHistory()))
		for _, result := range entry.GetHistory() {
			if result == nil {
				continue
			}
			history = append(history, contractroute.MatchResult{
				ListName: result.GetListName(),
				Matched:  result.GetMatched(),
			})
		}
		out = append(out, contractroute.MatchHistoryEntry{
			RuleName: entry.GetRuleName(),
			History:  history,
		})
	}
	return out
}
