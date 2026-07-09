package resolver

import (
	"context"
	"errors"

	contractresolver "github.com/Asutorufa/yuhaiin/pkg/contract/resolver"
)

type ContractController struct {
	resolver *ResolverCtr
}

func NewContractController(resolver *ResolverCtr) ContractController {
	return ContractController{resolver: resolver}
}

func (c ContractController) Save(ctx context.Context, resolver contractresolver.Resolver) (contractresolver.Resolver, error) {
	if c.resolver == nil {
		return contractresolver.Resolver{}, errors.New("resolver controller is unavailable")
	}
	return c.resolver.SaveContract(ctx, resolver)
}

func (c ContractController) Remove(ctx context.Context, id string) error {
	if c.resolver == nil {
		return errors.New("resolver controller is unavailable")
	}
	return c.resolver.RemoveContract(ctx, id)
}

type ContractConfigController struct {
	resolver *ResolverCtr
}

func NewContractConfigController(resolver *ResolverCtr) ContractConfigController {
	return ContractConfigController{resolver: resolver}
}

func (c ContractConfigController) Hosts(ctx context.Context) (contractresolver.Hosts, error) {
	if c.resolver == nil {
		return contractresolver.Hosts{}, errors.New("resolver controller is unavailable")
	}
	return c.resolver.ContractHosts(ctx)
}

func (c ContractConfigController) SaveHosts(ctx context.Context, hosts contractresolver.Hosts) (contractresolver.Hosts, error) {
	if c.resolver == nil {
		return contractresolver.Hosts{}, errors.New("resolver controller is unavailable")
	}
	return c.resolver.SaveContractHosts(ctx, hosts)
}

func (c ContractConfigController) FakeDNS(ctx context.Context) (contractresolver.FakeDNS, error) {
	if c.resolver == nil {
		return contractresolver.FakeDNS{}, errors.New("resolver controller is unavailable")
	}
	return c.resolver.ContractFakedns(ctx)
}

func (c ContractConfigController) SaveFakeDNS(ctx context.Context, config contractresolver.FakeDNS) (contractresolver.FakeDNS, error) {
	if c.resolver == nil {
		return contractresolver.FakeDNS{}, errors.New("resolver controller is unavailable")
	}
	return c.resolver.SaveContractFakedns(ctx, config)
}

func (c ContractConfigController) Server(ctx context.Context) (contractresolver.Server, error) {
	if c.resolver == nil {
		return contractresolver.Server{}, errors.New("resolver controller is unavailable")
	}
	return c.resolver.ContractServer(ctx)
}

func (c ContractConfigController) SaveServer(ctx context.Context, server contractresolver.Server) (contractresolver.Server, error) {
	if c.resolver == nil {
		return contractresolver.Server{}, errors.New("resolver controller is unavailable")
	}
	return c.resolver.SaveContractServer(ctx, server)
}
