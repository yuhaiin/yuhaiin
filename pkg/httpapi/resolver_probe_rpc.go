package httpapi

import (
	"context"

	contractresolver "github.com/Asutorufa/yuhaiin/pkg/contract/resolver"
	"github.com/Asutorufa/yuhaiin/pkg/resolver"
)

func (a v2API) resolverQueryTypes(context.Context, *emptyRequest) (*contractresolver.QueryTypeList, error) {
	return new(resolver.QueryTypes()), nil
}

func (a v2API) testResolver(ctx context.Context, request *contractresolver.TestRequest) (*contractresolver.TestResponse, error) {
	if err := request.Validate(); err != nil {
		return nil, badRequest(err)
	}
	if a.services.Resolver == nil {
		return nil, unavailable("resolver controller is unavailable")
	}
	return pointer(a.services.Resolver.Test(ctx, *request))
}
