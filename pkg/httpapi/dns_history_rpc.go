package httpapi

import (
	"context"
	"errors"

	contractdnshistory "github.com/Asutorufa/yuhaiin/pkg/contract/dnshistory"
	"github.com/Asutorufa/yuhaiin/pkg/statistics"
)

// DNSHistoryController serves the DNS query history. Records reveal visited
// domains and client processes, so reads require dns-history:read.
type DNSHistoryController interface {
	List(context.Context, contractdnshistory.ListRequest) (contractdnshistory.ListResponse, error)
	Get(context.Context, int64) (contractdnshistory.Record, error)
	Stats(context.Context, contractdnshistory.StatsRequest) (contractdnshistory.Stats, error)
	Clear(context.Context) (contractdnshistory.ClearResponse, error)
	Settings() contractdnshistory.Settings
	SaveSettings(context.Context, contractdnshistory.Settings) (contractdnshistory.Settings, error)
}

func registerDNSHistoryRoutes(handlers *v2Handlers, api v2API) {
	addRPCRoute(handlers, v2DNSHistoryList, api.dnsHistoryList)
	addRPCRoute(handlers, v2DNSHistoryGet, api.dnsHistoryGet)
	addRPCRoute(handlers, v2DNSHistoryStats, api.dnsHistoryStats)
	addRPCRoute(handlers, v2DNSHistoryClear, api.dnsHistoryClear)
	addRPCRoute(handlers, v2DNSHistorySettingsGet, api.dnsHistorySettings)
	addRPCRoute(handlers, v2DNSHistorySettingsPut, api.saveDNSHistorySettings)
}

func (a v2API) dnsHistory() (DNSHistoryController, error) {
	if a.services.DNSHistory == nil {
		return nil, unavailable("dns history is unavailable")
	}
	return a.services.DNSHistory, nil
}

func dnsHistoryError(err error) error {
	switch {
	case errors.Is(err, statistics.ErrDNSHistoryBadRequest):
		return badRequest(err)
	case errors.Is(err, statistics.ErrDNSHistoryNotFound):
		return notFound(err)
	}
	return err
}

func (a v2API) dnsHistoryList(ctx context.Context, request *contractdnshistory.ListRequest) (*contractdnshistory.ListResponse, error) {
	h, err := a.dnsHistory()
	if err != nil {
		return nil, err
	}
	out, err := h.List(ctx, *request)
	return pointer(out, dnsHistoryError(err))
}

func (a v2API) dnsHistoryGet(ctx context.Context, request *contractdnshistory.GetRequest) (*contractdnshistory.Record, error) {
	h, err := a.dnsHistory()
	if err != nil {
		return nil, err
	}
	if request.ID <= 0 {
		return nil, badRequest(errors.New("id is required"))
	}
	out, err := h.Get(ctx, request.ID)
	return pointer(out, dnsHistoryError(err))
}

func (a v2API) dnsHistoryStats(ctx context.Context, request *contractdnshistory.StatsRequest) (*contractdnshistory.Stats, error) {
	h, err := a.dnsHistory()
	if err != nil {
		return nil, err
	}
	out, err := h.Stats(ctx, *request)
	return pointer(out, dnsHistoryError(err))
}

func (a v2API) dnsHistoryClear(ctx context.Context, _ *emptyRequest) (*contractdnshistory.ClearResponse, error) {
	h, err := a.dnsHistory()
	if err != nil {
		return nil, err
	}
	return pointer(h.Clear(ctx))
}

func (a v2API) dnsHistorySettings(context.Context, *emptyRequest) (*contractdnshistory.Settings, error) {
	h, err := a.dnsHistory()
	if err != nil {
		return nil, err
	}
	return pointer(h.Settings(), nil)
}

func (a v2API) saveDNSHistorySettings(ctx context.Context, request *contractdnshistory.Settings) (*contractdnshistory.Settings, error) {
	h, err := a.dnsHistory()
	if err != nil {
		return nil, err
	}
	if err := statistics.ValidateDNSHistorySettings(*request); err != nil {
		return nil, badRequest(err)
	}
	return pointer(h.SaveSettings(ctx, *request))
}
