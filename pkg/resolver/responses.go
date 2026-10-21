package resolver

import (
	"context"
	"errors"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/resolver"
	dnssystem "github.com/Asutorufa/yuhaiin/pkg/net/dns/system"
)

func (c ContractConfigController) ResponseRules(ctx context.Context) (contract.ResponseRules, error) {
	if c.resolver == nil {
		return contract.ResponseRules{}, errors.New("resolver controller is unavailable")
	}
	store, ok := c.resolver.config.(contract.ResponseRulesController)
	if !ok {
		return contract.ResponseRules{}, errors.New("DNS response rules store is unavailable")
	}
	return store.ResponseRules(ctx)
}

func (c ContractConfigController) SaveResponseRules(ctx context.Context, config contract.ResponseRules) (contract.ResponseRules, error) {
	if c.resolver == nil || c.resolver.responses == nil {
		return config, errors.New("DNS response rules runtime is unavailable")
	}
	r := c.resolver
	r.responsesMu.Lock()
	defer r.responsesMu.Unlock()
	if err := config.Validate(); err != nil {
		return config, err
	}
	store, ok := r.config.(contract.ResponseRulesController)
	if !ok {
		return config, errors.New("DNS response rules store is unavailable")
	}
	next, err := store.SaveResponseRules(ctx, config)
	if err != nil {
		return config, err
	}
	if err := r.responses.Apply(next); err != nil {
		return next, err
	}
	dnssystem.RefreshCache()
	return next, nil
}
