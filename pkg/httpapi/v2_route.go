package httpapi

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

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

func registerRouteV2(register RegisterFunc, services V2Services) {
	registerV2Get(register, "GET /api/v2/route/config", services.RouteSettings, "route settings store is unavailable", func(store *plainstore.RouteSettingsStore, r *http.Request) (contractroute.Config, error) {
		config, err := store.Settings(r.Context())
		return routeConfigFromStoreV2(config), err
	})

	registerV2Available(register, "PUT /api/v2/route/config", services.RouteSettings != nil || services.Rules != nil, "route settings service is unavailable", func(w http.ResponseWriter, r *http.Request) error {
		var req contractroute.Config
		if err := readJSONBody(r, &req); err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		if services.Rules != nil {
			if err := services.Rules.SaveConfig(r.Context(), req); err != nil {
				return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
			}
		}
		if services.RouteSettings != nil {
			if err := services.RouteSettings.SaveSettings(r.Context(), routeConfigToStoreV2(req)); err != nil {
				return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
			}
		}
		return writeJSON(w, http.StatusOK, req)
	})

	registerV2Available(register, "GET /api/v2/route/lists", services.RouteLists != nil, "route list store is unavailable", func(w http.ResponseWriter, r *http.Request) error {
		items, err := services.RouteLists.ListRouteLists(r.Context())
		if err != nil {
			return err
		}
		query := strings.TrimSpace(r.URL.Query().Get("query"))
		if query != "" {
			items = filterRouteListItems(items, query)
		}
		page, pageSize := pageV2FromQuery(r)
		total := len(items)
		items = paginateV2(items, page, pageSize)
		return writeJSON(w, http.StatusOK, contractroute.RouteList{
			Items: items,
			Page:  contractroute.Page{Page: page, PageSize: pageSize, Total: total},
		})
	})

	registerV2Get(register, "GET /api/v2/route/lists/config", services.RouteSettings, "route settings store is unavailable", func(store *plainstore.RouteSettingsStore, r *http.Request) (contractroute.ListConfig, error) {
		config, err := store.ListSettings(r.Context())
		return routeListConfigFromStoreV2(config), err
	})

	registerV2Available(register, "PUT /api/v2/route/lists/config", services.RouteSettings != nil || services.Lists != nil, "route list settings service is unavailable", func(w http.ResponseWriter, r *http.Request) error {
		var req contractroute.ListConfig
		if err := readJSONBody(r, &req); err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		interval, err := strconv.ParseUint(req.RefreshInterval, 10, 64)
		if err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		if services.Lists != nil {
			if err := services.Lists.SaveConfig(r.Context(), req, interval); err != nil {
				return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
			}
		}
		if services.RouteSettings != nil {
			if err := services.RouteSettings.SaveListSettings(r.Context(), routeListConfigToStoreV2(req, interval)); err != nil {
				return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
			}
		}
		return writeJSON(w, http.StatusOK, req)
	})

	registerV2Action(register, "POST /api/v2/route/lists/refresh", services.Lists, "list controller is unavailable", http.StatusNoContent, 0, func(service ListRuntimeController, r *http.Request) error {
		return service.Refresh(r.Context())
	})

	registerV2Available(register, "POST /api/v2/route/lists", services.RouteLists != nil, "route list store is unavailable", func(w http.ResponseWriter, r *http.Request) error {
		var req contractroute.RouteListDetail
		if err := readJSONBody(r, &req); err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		if err := services.RouteLists.SaveRouteList(r.Context(), req, 0); err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		return writeJSON(w, http.StatusCreated, req)
	})

	registerV2Available(register, "GET /api/v2/route/lists/{id}", services.RouteLists != nil, "route list store is unavailable", func(w http.ResponseWriter, r *http.Request) error {
		id, err := requiredPathValue(r, "id")
		if err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		list, err := services.RouteLists.GetRouteList(r.Context(), id)
		if errors.Is(err, plainstore.ErrNotFound) {
			return writeError(w, http.StatusNotFound, "not_found", err.Error())
		}
		if err != nil {
			return err
		}
		return writeJSON(w, http.StatusOK, list)
	})

	registerV2Available(register, "PUT /api/v2/route/lists/{id}", services.RouteLists != nil, "route list store is unavailable", func(w http.ResponseWriter, r *http.Request) error {
		id, err := requiredPathValue(r, "id")
		if err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		var req contractroute.RouteListDetail
		if err := readJSONBody(r, &req); err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		req.Name = id
		if err := services.RouteLists.SaveRouteList(r.Context(), req, 0); err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		return writeJSON(w, http.StatusOK, req)
	})

	registerV2Available(register, "DELETE /api/v2/route/lists/{id}", services.RouteLists != nil, "route list store is unavailable", func(w http.ResponseWriter, r *http.Request) error {
		id, err := requiredPathValue(r, "id")
		if err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		err = services.RouteLists.DeleteRouteList(r.Context(), id)
		if errors.Is(err, plainstore.ErrNotFound) {
			return writeError(w, http.StatusNotFound, "not_found", err.Error())
		}
		if err != nil {
			return err
		}
		return writeJSON(w, http.StatusNoContent, nil)
	})

	registerV2Available(register, "GET /api/v2/route/rules", services.RouteRules != nil, "route rule store is unavailable", func(w http.ResponseWriter, r *http.Request) error {
		entries, err := services.RouteRules.ListRules(r.Context())
		if err != nil {
			return err
		}
		query := strings.TrimSpace(r.URL.Query().Get("query"))
		if query != "" {
			entries = filterRouteRuleEntries(entries, query)
		}
		page, pageSize := pageV2FromQuery(r)
		total := len(entries)
		entries = paginateV2(entries, page, pageSize)
		resp := routeRuleListFromEntries(entries)
		resp.Page = contractroute.Page{Page: page, PageSize: pageSize, Total: total}
		return writeJSON(w, http.StatusOK, resp)
	})

	registerV2Available(register, "POST /api/v2/route/rules", services.RouteRules != nil, "route rule store is unavailable", func(w http.ResponseWriter, r *http.Request) error {
		var req contractroute.RouteRule
		if err := readJSONBody(r, &req); err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		if err := services.RouteRules.SaveRule(r.Context(), req, 0, 0); err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		return writeJSON(w, http.StatusCreated, req)
	})

	registerV2Available(register, "POST /api/v2/route/rules/priority", services.RouteRules != nil, "route rule store is unavailable", func(w http.ResponseWriter, r *http.Request) error {
		var req changeRulePriorityV2Request
		if err := readJSONBody(r, &req); err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		if err := validateRulePriorityOperateV2(req.Operate); err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		if err := services.RouteRules.ChangePriority(r.Context(), req.Source.Name, req.Target.Name, req.Operate); err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		return writeJSON(w, http.StatusNoContent, nil)
	})

	registerV2Available(register, "GET /api/v2/route/rules/{name}/{index}", services.RouteRules != nil, "route rule store is unavailable", func(w http.ResponseWriter, r *http.Request) error {
		index, err := routeRuleIndexFromRequest(r)
		if err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		entry, err := services.RouteRules.GetRule(r.Context(), index.Name)
		if errors.Is(err, plainstore.ErrNotFound) {
			return writeError(w, http.StatusNotFound, "not_found", err.Error())
		}
		if err != nil {
			return err
		}
		return writeJSON(w, http.StatusOK, entry.Rule)
	})

	registerV2Available(register, "PUT /api/v2/route/rules/{name}/{index}", services.RouteRules != nil, "route rule store is unavailable", func(w http.ResponseWriter, r *http.Request) error {
		index, err := routeRuleIndexFromRequest(r)
		if err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		var req contractroute.RouteRule
		if err := readJSONBody(r, &req); err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		req.Name = index.Name
		if uint64(index.Index) > uint64(^uint(0)>>1) {
			return writeError(w, http.StatusBadRequest, "bad_request", "rule index exceeds the supported priority range")
		}
		priority := int(index.Index)
		if entry, err := services.RouteRules.GetRule(r.Context(), index.Name); err == nil {
			priority = entry.Priority
		}
		if err := services.RouteRules.SaveRule(r.Context(), req, priority, 0); err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		return writeJSON(w, http.StatusOK, req)
	})

	registerV2Available(register, "DELETE /api/v2/route/rules/{name}/{index}", services.RouteRules != nil, "route rule store is unavailable", func(w http.ResponseWriter, r *http.Request) error {
		index, err := routeRuleIndexFromRequest(r)
		if err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		err = services.RouteRules.DeleteRule(r.Context(), index.Name)
		if errors.Is(err, plainstore.ErrNotFound) {
			return writeError(w, http.StatusNotFound, "not_found", err.Error())
		}
		if err != nil {
			return err
		}
		return writeJSON(w, http.StatusNoContent, nil)
	})

	registerV2Available(register, "POST /api/v2/route/rules/test", services.Rules != nil, "rule controller is unavailable", func(w http.ResponseWriter, r *http.Request) error {
		var req contractroute.RuleTestRequest
		if err := readJSONBody(r, &req); err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		resp, err := services.Rules.Test(r.Context(), req.Host)
		if err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		return writeJSON(w, http.StatusOK, resp)
	})

	registerV2Get(register, "GET /api/v2/route/rules/block-history", services.Rules, "rule controller is unavailable", func(service RouteRuntimeController, r *http.Request) (contractroute.BlockHistoryList, error) {
		return service.BlockHistory(r.Context())
	})

	registerV2Available(register, "GET /api/v2/route/tags", services.RouteTags != nil, "route tag store is unavailable", func(w http.ResponseWriter, r *http.Request) error {
		items, err := services.RouteTags.ListTags(r.Context())
		if err != nil {
			return err
		}
		query := strings.TrimSpace(r.URL.Query().Get("query"))
		if query != "" {
			items = filterRouteTags(items, query)
		}
		page, pageSize := pageV2FromQuery(r)
		total := len(items)
		items = paginateV2(items, page, pageSize)
		return writeJSON(w, http.StatusOK, contractroute.TagList{
			Items: items,
			Page:  contractroute.Page{Page: page, PageSize: pageSize, Total: total},
		})
	})

	registerV2Available(register, "PUT /api/v2/route/tags/{tag}", services.RouteTags != nil, "route tag store is unavailable", func(w http.ResponseWriter, r *http.Request) error {
		tag, err := requiredPathValue(r, "tag")
		if err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		var req contractroute.SaveTagRequest
		if err := readJSONBody(r, &req); err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		req.Tag = tag
		if err := services.RouteTags.SaveTag(r.Context(), contractroute.TagItem{
			Name: req.Tag,
			Type: req.Type,
			Hash: []string{req.Hash},
		}, 0); err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		return writeJSON(w, http.StatusNoContent, nil)
	})

	registerV2Available(register, "DELETE /api/v2/route/tags/{tag}", services.RouteTags != nil, "route tag store is unavailable", func(w http.ResponseWriter, r *http.Request) error {
		tag, err := requiredPathValue(r, "tag")
		if err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		err = services.RouteTags.DeleteTag(r.Context(), tag)
		if errors.Is(err, plainstore.ErrNotFound) {
			return writeError(w, http.StatusNotFound, "not_found", err.Error())
		}
		if err != nil {
			return err
		}
		return writeJSON(w, http.StatusNoContent, nil)
	})
}

func routeRuleListFromEntries(entries []plainstore.RouteRuleEntry) contractroute.RuleList {
	items := make([]contractroute.RuleItem, 0, len(entries))
	for _, entry := range entries {
		rule := entry.Rule
		items = append(items, contractroute.RuleItem{
			Name:      rule.Name,
			Disabled:  rule.Disabled,
			Index:     uint32(entry.Priority),
			Mode:      rule.Mode,
			Tag:       rule.Tag,
			Resolver:  rule.Resolver,
			RuleCount: uint32(len(rule.Rules)),
		})
	}
	return contractroute.RuleList{Items: items}
}

func filterRouteListItems(items []contractroute.ListItem, query string) []contractroute.ListItem {
	query = strings.ToLower(strings.TrimSpace(query))
	if query == "" {
		return items
	}
	out := make([]contractroute.ListItem, 0, len(items))
	for _, item := range items {
		if strings.Contains(strings.ToLower(item.Name), query) ||
			strings.Contains(strings.ToLower(item.Type), query) ||
			strings.Contains(strings.ToLower(item.Source), query) ||
			strings.Contains(strings.ToLower(item.Preview), query) {
			out = append(out, item)
		}
	}
	return out
}

func filterRouteRuleEntries(entries []plainstore.RouteRuleEntry, query string) []plainstore.RouteRuleEntry {
	query = strings.ToLower(strings.TrimSpace(query))
	if query == "" {
		return entries
	}
	out := make([]plainstore.RouteRuleEntry, 0, len(entries))
	for _, entry := range entries {
		rule := entry.Rule
		if strings.Contains(strings.ToLower(rule.Name), query) ||
			strings.Contains(strings.ToLower(rule.Mode), query) ||
			strings.Contains(strings.ToLower(rule.Tag), query) ||
			strings.Contains(strings.ToLower(rule.Resolver), query) {
			out = append(out, entry)
		}
	}
	return out
}

func filterRouteTags(items []contractroute.TagItem, query string) []contractroute.TagItem {
	query = strings.ToLower(strings.TrimSpace(query))
	if query == "" {
		return items
	}
	out := make([]contractroute.TagItem, 0, len(items))
	for _, item := range items {
		if strings.Contains(strings.ToLower(item.Name), query) ||
			strings.Contains(strings.ToLower(item.Type), query) ||
			strings.Contains(strings.ToLower(strings.Join(item.Hash, "\n")), query) {
			out = append(out, item)
		}
	}
	return out
}

func routeRuleIndexFromRequest(r *http.Request) (ruleIndexV2, error) {
	name, err := requiredPathValue(r, "name")
	if err != nil {
		return ruleIndexV2{}, err
	}
	indexRaw, err := requiredPathValue(r, "index")
	if err != nil {
		return ruleIndexV2{}, err
	}
	index, err := strconv.ParseUint(indexRaw, 10, 32)
	if err != nil {
		return ruleIndexV2{}, err
	}
	return ruleIndexV2{Name: name, Index: uint32(index)}, nil
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
	return contractroute.Config{
		DirectResolver:       value.DirectResolver,
		ProxyResolver:        value.ProxyResolver,
		ResolveLocally:       value.ResolveLocally,
		UdpProxyFqdnStrategy: udpProxyFqdnStrategyToStringV2(value.UDPProxyFQDN),
	}
}

func routeConfigToStoreV2(value contractroute.Config) plainstore.RouteSettings {
	return plainstore.RouteSettings{
		DirectResolver: value.DirectResolver,
		ProxyResolver:  value.ProxyResolver,
		ResolveLocally: value.ResolveLocally,
		UDPProxyFQDN:   udpProxyFqdnStrategyFromStringV2(value.UdpProxyFqdnStrategy),
	}
}

func routeListConfigFromStoreV2(value plainstore.RouteListSettings) contractroute.ListConfig {
	return contractroute.ListConfig{
		RefreshInterval: strconv.FormatUint(value.RefreshInterval, 10),
		LastRefreshTime: strconv.FormatUint(value.LastRefreshTime, 10),
		Error:           value.Error,
		MaxMindDBGeoIP: contractroute.MaxMindDBGeoIP{
			DownloadURL: value.MaxMindDBDownloadURL,
			Error:       value.MaxMindDBError,
		},
	}
}

func routeListConfigToStoreV2(value contractroute.ListConfig, refreshInterval uint64) plainstore.RouteListSettings {
	lastRefreshTime, _ := strconv.ParseUint(value.LastRefreshTime, 10, 64)
	return plainstore.RouteListSettings{
		RefreshInterval:      refreshInterval,
		LastRefreshTime:      lastRefreshTime,
		Error:                value.Error,
		MaxMindDBDownloadURL: value.MaxMindDBGeoIP.DownloadURL,
		MaxMindDBError:       value.MaxMindDBGeoIP.Error,
	}
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
