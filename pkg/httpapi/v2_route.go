package httpapi

import (
	"fmt"
	"strconv"

	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
)

type changeRulePriorityV2Request struct {
	Source  ruleIndexV2 `json:"source"`
	Target  ruleIndexV2 `json:"target"`
	Operate string      `json:"operate"`
}

type ruleIndexV2 struct {
	Name  string `json:"name"`
	Index uint32 `json:"index"`
}

func routeRuleListFromEntries(entries []plainstore.RouteRuleEntry) contractroute.RuleList {
	items := make([]contractroute.RuleItem, 0, len(entries))
	for _, entry := range entries {
		rule := entry.Rule
		items = append(items, contractroute.RuleItem{Name: rule.Name, Disabled: rule.Disabled, Index: uint32(entry.Priority), Mode: rule.Mode, Tag: rule.Tag, Resolver: rule.Resolver, RuleCount: uint32(len(rule.Rules))})
	}
	return contractroute.RuleList{Items: items}
}
func validateRulePriorityOperateV2(value string) error {
	switch value {
	case "", "exchange", "insert_before", "insert_after":
		return nil
	default:
		return fmt.Errorf("unknown priority operate %q", value)
	}
}
func routeConfigFromStoreV2(value plainstore.RouteSettings) contractroute.Config {
	return contractroute.Config{DirectResolver: value.DirectResolver, ProxyResolver: value.ProxyResolver, ResolveLocally: value.ResolveLocally, UdpProxyFqdnStrategy: udpProxyFqdnStrategyToStringV2(value.UDPProxyFQDN)}
}
func routeConfigToStoreV2(value contractroute.Config) plainstore.RouteSettings {
	return plainstore.RouteSettings{DirectResolver: value.DirectResolver, ProxyResolver: value.ProxyResolver, ResolveLocally: value.ResolveLocally, UDPProxyFQDN: udpProxyFqdnStrategyFromStringV2(value.UdpProxyFqdnStrategy)}
}
func routeListConfigFromStoreV2(value plainstore.RouteListSettings) contractroute.ListConfig {
	return contractroute.ListConfig{RefreshInterval: strconv.FormatUint(value.RefreshInterval, 10), LastRefreshTime: strconv.FormatUint(value.LastRefreshTime, 10), Error: value.Error, HostIndexDisk: value.HostIndexDisk, MaxMindDBGeoIP: contractroute.MaxMindDBGeoIP{DownloadURL: value.MaxMindDBDownloadURL, Error: value.MaxMindDBError}}
}
func routeListConfigToStoreV2(value contractroute.ListConfig, refreshInterval uint64) plainstore.RouteListSettings {
	lastRefreshTime, _ := strconv.ParseUint(value.LastRefreshTime, 10, 64)
	return plainstore.RouteListSettings{RefreshInterval: refreshInterval, LastRefreshTime: lastRefreshTime, Error: value.Error, HostIndexDisk: value.HostIndexDisk, MaxMindDBDownloadURL: value.MaxMindDBGeoIP.DownloadURL, MaxMindDBError: value.MaxMindDBGeoIP.Error}
}
func udpProxyFqdnStrategyToStringV2(value int) string {
	switch value {
	case 1:
		return "resolve"
	case 2:
		return "skip_resolve"
	default:
		return "default"
	}
}
func udpProxyFqdnStrategyFromStringV2(value string) int {
	switch value {
	case "resolve", "udp_proxy_fqdn_strategy_resolve":
		return 1
	case "skip_resolve", "udp_proxy_fqdn_strategy_skip_resolve":
		return 2
	default:
		return 0
	}
}
