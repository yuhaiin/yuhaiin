package httpapi

import (
	"context"
	"errors"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/resolver"
)

func (a v2API) responseRulesController() (contract.ResponseRulesController, error) {
	if controller, ok := a.services.ResolverConfig.(contract.ResponseRulesController); ok {
		return controller, nil
	}
	return nil, unavailable("DNS response rules controller is unavailable")
}

func (a v2API) responseRules(ctx context.Context, _ *emptyRequest) (*contract.ResponseRules, error) {
	controller, err := a.responseRulesController()
	if err != nil {
		return nil, err
	}
	return pointer(controller.ResponseRules(ctx))
}

func (a v2API) saveResponseRules(ctx context.Context, request *contract.ResponseRules) (*contract.ResponseRules, error) {
	if err := request.Validate(); err != nil {
		return nil, badRequest(err)
	}
	controller, err := a.responseRulesController()
	if err != nil {
		return nil, err
	}
	next, err := controller.SaveResponseRules(ctx, *request)
	if errors.Is(err, contract.ErrInvalidResponseRule) {
		return nil, badRequest(err)
	}
	return new(next), err
}
