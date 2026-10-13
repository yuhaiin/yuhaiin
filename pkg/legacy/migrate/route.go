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
			Target:    legacyTarget(item.Tag),
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
	out, _ := convertLegacyRuleWithWarnings(in)
	return out
}

func convertLegacyRuleWithWarnings(in *schemaconfig.Rulev2) (contractroute.RouteRule, []Warning) {
	if in == nil {
		return contractroute.RouteRule{Mode: "bypass"}, nil
	}
	mode := in.GetMode().String()
	resolveStrategy := in.GetResolveStrategy().String()
	udpProxyFQDNStrategy := in.GetUdpProxyFqdnStrategy().String()
	var warnings []Warning
	if _, ok := schemaconfig.Mode_name[int32(in.GetMode())]; !ok {
		warnings = append(warnings, Warning{Entity: in.GetName(), Message: fmt.Sprintf("unknown legacy route mode %d; migrated as bypass", in.GetMode())})
		mode = "bypass"
	}
	if _, ok := schemaconfig.ResolveStrategy_name[int32(in.GetResolveStrategy())]; !ok {
		warnings = append(warnings, Warning{Entity: in.GetName(), Message: fmt.Sprintf("unknown legacy resolve strategy %d; migrated as default", in.GetResolveStrategy())})
		resolveStrategy = "default"
	}
	if _, ok := schemaconfig.UdpProxyFqdnStrategy_name[int32(in.GetUdpProxyFqdnStrategy())]; !ok {
		warnings = append(warnings, Warning{Entity: in.GetName(), Message: fmt.Sprintf("unknown legacy UDP FQDN strategy %d; migrated as default", in.GetUdpProxyFqdnStrategy())})
		udpProxyFQDNStrategy = "udp_proxy_fqdn_strategy_default"
	}

	out := contractroute.RouteRule{
		Name:                 in.GetName(),
		Mode:                 mode,
		Target:               legacyTarget(in.GetTag()),
		ResolveStrategy:      resolveStrategy,
		UdpProxyFqdnStrategy: udpProxyFQDNStrategy,
		Resolver:             in.GetResolver(),
		Disabled:             in.GetDisabled(),

		Rules: make([]contractroute.RuleExpr, 0, len(in.GetRules()))}
	for index, group := range in.GetRules() {
		if group == nil {
			continue
		}
		all := make([]contractroute.RuleExpr, 0, len(group.GetRules()))
		for childIndex, rule := range group.GetRules() {
			if message := legacyRuleExprWarning(rule); message != "" {
				warnings = append(warnings, Warning{
					Entity:  out.Name,
					Message: fmt.Sprintf("rules[%d].all[%d]: %s", index, childIndex, message),
				})
				continue
			}
			if expr, ok := convertLegacyRuleExpr(rule); ok {
				all = append(all, expr)
			}
		}
		if len(group.GetRules()) > 0 && len(all) == 0 {
			warnings = append(warnings, Warning{
				Entity:  out.Name,
				Message: fmt.Sprintf("rules[%d] contains no supported matchers and was skipped", index),
			})
			continue
		}
		if len(all) == 0 {
			out.Rules = append(out.Rules, contractroute.RuleExpr{Type: "always", Always: &contractroute.MatchAllExpr{}})
		} else {
			out.Rules = append(out.Rules, contractroute.RuleExpr{Type: "all", All: all})
		}
	}
	return out, warnings
}

func legacyRuleExprWarning(in *schemaconfig.Rule) string {
	if in == nil || in.WhichObject() != schemaconfig.Rule_Network_case {
		return ""
	}
	if _, ok := schemaconfig.NetworkNetworkType_name[int32(in.GetNetwork().GetNetwork())]; !ok {
		return fmt.Sprintf("unknown legacy network %d; matcher was skipped", in.GetNetwork().GetNetwork())
	}
	return ""
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
	if in.Type != "" {
		if _, ok := schemaconfig.ListListTypeEnum_value[in.Type]; !ok {
			return nil, fmt.Errorf("unsupported route list type %q", in.Type)
		}
	}
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
	case "", "local":
		var lists []string
		if in.Source.Local != nil {
			lists = append([]string(nil), in.Source.Local.Lists...)
		}
		out.Local = &schemaconfig.ListLocal{Lists: lists}
	default:
		return nil, fmt.Errorf("unsupported route list source %q", in.Source.Type)
	}
	return out, nil
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
		out.Target = legacyTarget(in.Mode.GetTag())
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

func legacyTarget(name string) contractroute.Target {
	if name == "" {
		return contractroute.Target{Type: "default"}
	}
	return contractroute.Target{Type: "selector", ID: name}
}
