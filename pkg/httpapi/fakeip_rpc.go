package httpapi

import (
	"context"
	"errors"
	"net/netip"

	contractresolver "github.com/Asutorufa/yuhaiin/pkg/contract/resolver"
	"github.com/Asutorufa/yuhaiin/pkg/net/dns/fakeip"
)

func (a v2API) fakeIPEntries(ctx context.Context, request *listRequest) (*listV2[contractresolver.FakeIPEntry], error) {
	if a.services.FakeIP == nil {
		return nil, unavailable("fakeip controller is unavailable")
	}
	page, size := max(1, request.Page), request.PageSize
	if size <= 0 {
		size = fakeip.DefaultPageSize
	}
	size = min(size, fakeip.MaxPageSize)
	items, total, err := a.services.FakeIP.ListFakeIPEntries(ctx, page, size, request.Query)
	if err != nil {
		return nil, err
	}
	return &listV2[contractresolver.FakeIPEntry]{Items: items, Page: pageV2{Page: page, PageSize: size, Total: total}}, nil
}

func (a v2API) deleteFakeIPEntry(ctx context.Context, request *contractresolver.FakeIPEntry) (*contractresolver.FakeIPDeleteResponse, error) {
	ip, err := netip.ParseAddr(request.IP)
	if err != nil || ip.Zone() != "" || request.Domain == "" {
		return nil, badRequest(errors.New("domain and valid fakeip address are required"))
	}
	if a.services.FakeIP == nil {
		return nil, unavailable("fakeip controller is unavailable")
	}
	return pointer(a.services.FakeIP.DeleteFakeIPEntry(ctx, *request))
}
