package httpapi

import (
	"context"
	"errors"
	"strconv"
	"strings"

	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
)

func addRouteRPCRoutesV2(handlers *v2Handlers, services V2Services) {
	api := v2API{services: services}
	addRPCRoute(handlers, v2RouteActivation, api.routeActivation)
	addRPCRoute(handlers, v2RouteApply, api.applyRoute)
	addRPCRoute(handlers, v2RouteConfigGet, api.routeConfig)
	addRPCRoute(handlers, v2RouteConfigPut, api.saveRouteConfig)
	addRPCRoute(handlers, v2RouteListsGet, api.routeLists)
	addRPCRoute(handlers, v2RouteListConfigGet, api.routeListConfig)
	addRPCRoute(handlers, v2RouteListConfigPut, api.saveRouteListConfig)
	addRPCRoute(handlers, v2RouteListRefresh, api.refreshRouteLists)
	addRPCRoute(handlers, v2RouteListActivation, api.routeListActivation)
	addRPCRoute(handlers, v2RouteListsPost, api.createRouteList)
	addRPCRoute(handlers, v2RouteListGet, api.routeList)
	addRPCRoute(handlers, v2RouteListPut, api.saveRouteList)
	addRPCRoute(handlers, v2RouteListDelete, api.deleteRouteList)
	addRPCRoute(handlers, v2RouteRulesGet, api.routeRules)
	addRPCRoute(handlers, v2RouteRulesPost, api.createRouteRule)
	addRPCRoute(handlers, v2RouteRulesPriority, api.changeRouteRulePriority)
	addRPCRoute(handlers, v2RouteRuleGet, api.routeRule)
	addRPCRoute(handlers, v2RouteRulePut, api.saveRouteRule)
	addRPCRoute(handlers, v2RouteRuleDelete, api.deleteRouteRule)
	addRPCRoute(handlers, v2RouteRulesTest, api.testRouteRule)
	addRPCRoute(handlers, v2RouteRulesBlockHistory, api.routeBlockHistory)
	addRPCRoute(handlers, v2RouteTagsGet, api.routeTags)
	addRPCRoute(handlers, v2RouteTagPut, api.saveRouteTag)
	addRPCRoute(handlers, v2RouteTagDelete, api.deleteRouteTag)
}

func (a v2API) routeActivation(ctx context.Context, _ *emptyRequest) (*contractroute.ActivationStatus, error) {
	if a.services.Lists == nil && a.services.Rules == nil {
		return nil, unavailable("route runtime is unavailable")
	}
	result := contractroute.ActivationStatus{}
	if a.services.Lists != nil {
		status, err := a.services.Lists.ActivationStatus(ctx)
		if err != nil {
			return nil, err
		}
		result.HostIndexRefreshAt = status.HostIndexRefreshAt
	}
	if a.services.Rules != nil {
		status, err := a.services.Rules.ActivationStatus(ctx)
		if err != nil {
			return nil, err
		}
		result.RuleApplyAt = status.ApplyAt
	}
	return &result, nil
}
func (a v2API) applyRoute(ctx context.Context, _ *emptyRequest) (*emptyResponse, error) {
	if a.services.Lists == nil && a.services.Rules == nil {
		return nil, unavailable("route runtime is unavailable")
	}
	if a.services.Lists != nil {
		if err := a.services.Lists.Apply(ctx); err != nil {
			return nil, err
		}
	}
	if a.services.Rules != nil {
		if err := a.services.Rules.Apply(ctx); err != nil {
			return nil, err
		}
	}
	return &emptyResponse{}, nil
}
func (a v2API) routeConfig(ctx context.Context, _ *emptyRequest) (*contractroute.Config, error) {
	if a.services.RouteSettings == nil {
		return nil, unavailable("route settings store is unavailable")
	}
	value, err := a.services.RouteSettings.Settings(ctx)
	if err != nil {
		return nil, err
	}
	result := routeConfigFromStoreV2(value)
	return &result, nil
}
func (a v2API) saveRouteConfig(ctx context.Context, request *contractroute.Config) (*contractroute.Config, error) {
	if a.services.RouteSettings == nil && a.services.Rules == nil {
		return nil, unavailable("route settings service is unavailable")
	}
	if a.services.Rules != nil {
		if err := a.services.Rules.SaveConfig(ctx, *request); err != nil {
			return nil, badRequest(err)
		}
	}
	if a.services.RouteSettings != nil {
		if err := a.services.RouteSettings.SaveSettings(ctx, routeConfigToStoreV2(*request)); err != nil {
			return nil, badRequest(err)
		}
	}
	return request, nil
}
func (a v2API) routeLists(ctx context.Context, request *listRequest) (*contractroute.RouteList, error) {
	if a.services.RouteLists == nil {
		return nil, unavailable("route list store is unavailable")
	}
	items, err := a.services.RouteLists.ListRouteLists(ctx)
	if err != nil {
		return nil, err
	}
	if query := strings.TrimSpace(request.Query); query != "" {
		items = filterRouteListItems(items, query)
	}
	page := max(request.Page, 1)
	size := max(request.PageSize, 0)
	return &contractroute.RouteList{Items: paginateV2(items, page, size), Page: contractroute.Page{Page: page, PageSize: size, Total: len(items)}}, nil
}
func (a v2API) routeListConfig(ctx context.Context, _ *emptyRequest) (*contractroute.ListConfig, error) {
	if a.services.RouteSettings == nil {
		return nil, unavailable("route settings store is unavailable")
	}
	value, err := a.services.RouteSettings.ListSettings(ctx)
	if err != nil {
		return nil, err
	}
	result := routeListConfigFromStoreV2(value)
	return &result, nil
}
func (a v2API) saveRouteListConfig(ctx context.Context, request *contractroute.ListConfig) (*contractroute.ListConfig, error) {
	if a.services.RouteSettings == nil && a.services.Lists == nil {
		return nil, unavailable("route list settings service is unavailable")
	}
	interval, err := strconv.ParseUint(request.RefreshInterval, 10, 64)
	if err != nil {
		return nil, badRequest(err)
	}
	if a.services.Lists != nil {
		if err := a.services.Lists.SaveConfig(ctx, *request, interval); err != nil {
			return nil, badRequest(err)
		}
	} else if err := a.services.RouteSettings.SaveListSettings(ctx, routeListConfigToStoreV2(*request, interval)); err != nil {
		return nil, badRequest(err)
	}
	if a.services.RouteSettings == nil {
		return request, nil
	}
	stored, err := a.services.RouteSettings.ListSettings(ctx)
	if err != nil {
		return nil, err
	}
	result := routeListConfigFromStoreV2(stored)
	return &result, nil
}
func (a v2API) refreshRouteLists(ctx context.Context, _ *emptyRequest) (*emptyResponse, error) {
	if a.services.Lists == nil {
		return nil, unavailable("list controller is unavailable")
	}
	if err := a.services.Lists.Refresh(ctx); err != nil {
		return nil, err
	}
	return &emptyResponse{}, nil
}
func (a v2API) routeListActivation(ctx context.Context, _ *emptyRequest) (*contractroute.ListActivationStatus, error) {
	if a.services.Lists == nil {
		return nil, unavailable("list controller is unavailable")
	}
	return pointer(a.services.Lists.ActivationStatus(ctx))
}
func (a v2API) createRouteList(ctx context.Context, request *contractroute.RouteListDetail) (*contractroute.RouteListDetail, error) {
	if a.services.RouteLists == nil {
		return nil, unavailable("route list store is unavailable")
	}
	if err := a.services.RouteLists.SaveRouteList(ctx, *request, 0); err != nil {
		return nil, badRequest(err)
	}
	if a.services.Lists != nil {
		if err := a.services.Lists.ApplyChanges(ctx); err != nil {
			return nil, err
		}
	}
	return request, nil
}
func (a v2API) routeList(ctx context.Context, request *idRequest) (*contractroute.RouteListDetail, error) {
	if a.services.RouteLists == nil {
		return nil, unavailable("route list store is unavailable")
	}
	value, err := a.services.RouteLists.GetRouteList(ctx, request.ID)
	if errors.Is(err, plainstore.ErrNotFound) {
		return nil, notFound(err)
	}
	if err != nil {
		return nil, err
	}
	return &value, nil
}

type routeListSaveRequest struct {
	ID string `json:"id"`
	contractroute.RouteListDetail
}

func (a v2API) saveRouteList(ctx context.Context, request *routeListSaveRequest) (*contractroute.RouteListDetail, error) {
	if a.services.RouteLists == nil {
		return nil, unavailable("route list store is unavailable")
	}
	request.Name = request.ID
	if err := a.services.RouteLists.SaveRouteList(ctx, request.RouteListDetail, 0); err != nil {
		return nil, badRequest(err)
	}
	if a.services.Lists != nil {
		if err := a.services.Lists.ApplyChanges(ctx); err != nil {
			return nil, err
		}
	}
	return &request.RouteListDetail, nil
}
func (a v2API) deleteRouteList(ctx context.Context, request *idRequest) (*emptyResponse, error) {
	if a.services.RouteLists == nil {
		return nil, unavailable("route list store is unavailable")
	}
	if err := a.services.RouteLists.DeleteRouteList(ctx, request.ID); err != nil {
		if errors.Is(err, plainstore.ErrNotFound) {
			return nil, notFound(err)
		}
		return nil, err
	}
	if a.services.Lists != nil {
		if err := a.services.Lists.ApplyChanges(ctx); err != nil {
			return nil, err
		}
	}
	return &emptyResponse{}, nil
}
func (a v2API) routeRules(ctx context.Context, request *listRequest) (*contractroute.RuleList, error) {
	if a.services.RouteRules == nil {
		return nil, unavailable("route rule store is unavailable")
	}
	entries, err := a.services.RouteRules.ListRules(ctx)
	if err != nil {
		return nil, err
	}
	if query := strings.TrimSpace(request.Query); query != "" {
		entries = filterRouteRuleEntries(entries, query)
	}
	page := max(request.Page, 1)
	size := max(request.PageSize, 0)
	response := routeRuleListFromEntries(paginateV2(entries, page, size))
	response.Page = contractroute.Page{Page: page, PageSize: size, Total: len(entries)}
	return &response, nil
}
func (a v2API) createRouteRule(ctx context.Context, request *contractroute.RouteRule) (*contractroute.RouteRule, error) {
	if a.services.RouteRules == nil {
		return nil, unavailable("route rule store is unavailable")
	}
	if err := a.services.RouteRules.SaveRule(ctx, *request, 0, 0); err != nil {
		return nil, badRequest(err)
	}
	a.scheduleRouteApply()
	return request, nil
}
func (a v2API) changeRouteRulePriority(ctx context.Context, request *changeRulePriorityV2Request) (*emptyResponse, error) {
	if a.services.RouteRules == nil {
		return nil, unavailable("route rule store is unavailable")
	}
	if err := validateRulePriorityOperateV2(request.Operate); err != nil {
		return nil, badRequest(err)
	}
	if err := a.services.RouteRules.ChangePriority(ctx, request.Source.Name, request.Target.Name, request.Operate); err != nil {
		return nil, badRequest(err)
	}
	a.scheduleRouteApply()
	return &emptyResponse{}, nil
}

type ruleRequest struct {
	Name  string `json:"name"`
	Index uint32 `json:"index"`
}

func (a v2API) routeRule(ctx context.Context, request *ruleRequest) (*contractroute.RouteRule, error) {
	if a.services.RouteRules == nil {
		return nil, unavailable("route rule store is unavailable")
	}
	entry, err := a.services.RouteRules.GetRule(ctx, request.Name)
	if errors.Is(err, plainstore.ErrNotFound) {
		return nil, notFound(err)
	}
	if err != nil {
		return nil, err
	}
	return &entry.Rule, nil
}

type routeRuleSaveRequest struct {
	Name  string `json:"name"`
	Index uint32 `json:"index"`
	contractroute.RouteRule
}

func (a v2API) saveRouteRule(ctx context.Context, request *routeRuleSaveRequest) (*contractroute.RouteRule, error) {
	if a.services.RouteRules == nil {
		return nil, unavailable("route rule store is unavailable")
	}
	request.RouteRule.Name = request.Name
	priority := int(request.Index)
	if entry, err := a.services.RouteRules.GetRule(ctx, request.Name); err == nil {
		priority = entry.Priority
	}
	if err := a.services.RouteRules.SaveRule(ctx, request.RouteRule, priority, 0); err != nil {
		return nil, badRequest(err)
	}
	a.scheduleRouteApply()
	return &request.RouteRule, nil
}
func (a v2API) deleteRouteRule(ctx context.Context, request *ruleRequest) (*emptyResponse, error) {
	if a.services.RouteRules == nil {
		return nil, unavailable("route rule store is unavailable")
	}
	if err := a.services.RouteRules.DeleteRule(ctx, request.Name); err != nil {
		if errors.Is(err, plainstore.ErrNotFound) {
			return nil, notFound(err)
		}
		return nil, err
	}
	a.scheduleRouteApply()
	return &emptyResponse{}, nil
}
func (a v2API) testRouteRule(ctx context.Context, request *contractroute.RuleTestRequest) (*contractroute.RuleTestResponse, error) {
	if a.services.Rules == nil {
		return nil, unavailable("rule controller is unavailable")
	}
	value, err := a.services.Rules.Test(ctx, request.Host)
	if err != nil {
		return nil, badRequest(err)
	}
	return &value, nil
}
func (a v2API) routeBlockHistory(ctx context.Context, _ *emptyRequest) (*contractroute.BlockHistoryList, error) {
	if a.services.Rules == nil {
		return nil, unavailable("rule controller is unavailable")
	}
	return pointer(a.services.Rules.BlockHistory(ctx))
}
func (a v2API) routeTags(ctx context.Context, request *listRequest) (*contractroute.TagList, error) {
	if a.services.RouteTags == nil {
		return nil, unavailable("route tag store is unavailable")
	}
	items, err := a.services.RouteTags.ListTags(ctx)
	if err != nil {
		return nil, err
	}
	if query := strings.TrimSpace(request.Query); query != "" {
		items = filterRouteTags(items, query)
	}
	page := max(request.Page, 1)
	size := max(request.PageSize, 0)
	return &contractroute.TagList{Items: paginateV2(items, page, size), Page: contractroute.Page{Page: page, PageSize: size, Total: len(items)}}, nil
}
func (a v2API) saveRouteTag(ctx context.Context, request *contractroute.SaveTagRequest) (*emptyResponse, error) {
	if a.services.RouteTags == nil {
		return nil, unavailable("route tag store is unavailable")
	}
	if err := a.services.RouteTags.SaveTag(ctx, contractroute.TagItem{Name: request.Tag, Type: request.Type, Hash: []string{request.Hash}}, 0); err != nil {
		return nil, badRequest(err)
	}
	return &emptyResponse{}, nil
}
func (a v2API) deleteRouteTag(ctx context.Context, request *contractroute.SaveTagRequest) (*emptyResponse, error) {
	if a.services.RouteTags == nil {
		return nil, unavailable("route tag store is unavailable")
	}
	if err := a.services.RouteTags.DeleteTag(ctx, request.Tag); err != nil {
		if errors.Is(err, plainstore.ErrNotFound) {
			return nil, notFound(err)
		}
		return nil, err
	}
	return &emptyResponse{}, nil
}
func (a v2API) scheduleRouteApply() {
	if a.services.Rules != nil {
		a.services.Rules.ScheduleApply()
	}
}
