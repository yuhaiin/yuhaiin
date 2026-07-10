package store

import (
	"context"

	contractresolver "github.com/Asutorufa/yuhaiin/pkg/contract/resolver"
)

type ResolverConfigRuntime interface {
	Hosts(context.Context) (contractresolver.Hosts, error)
	SaveHosts(context.Context, contractresolver.Hosts) (contractresolver.Hosts, error)
	FakeDNS(context.Context) (contractresolver.FakeDNS, error)
	SaveFakeDNS(context.Context, contractresolver.FakeDNS) (contractresolver.FakeDNS, error)
	Server(context.Context) (contractresolver.Server, error)
	SaveServer(context.Context, contractresolver.Server) (contractresolver.Server, error)
}

type ResolverConfigRuntimeStore struct {
	Store   *ResolverConfigStore
	Runtime ResolverConfigRuntime
}

func NewResolverConfigRuntimeStore(store *ResolverConfigStore, runtime ResolverConfigRuntime) *ResolverConfigRuntimeStore {
	return &ResolverConfigRuntimeStore{Store: store, Runtime: runtime}
}

func (s *ResolverConfigRuntimeStore) Hosts(ctx context.Context) (contractresolver.Hosts, error) {
	if s.Store != nil {
		return s.Store.Hosts(ctx)
	}
	return s.Runtime.Hosts(ctx)
}

func (s *ResolverConfigRuntimeStore) SaveHosts(ctx context.Context, hosts contractresolver.Hosts) (contractresolver.Hosts, error) {
	if s.Runtime != nil {
		next, err := s.Runtime.SaveHosts(ctx, hosts)
		if err != nil {
			return contractresolver.Hosts{}, err
		}
		hosts = next
	}
	if s.Store != nil {
		return s.Store.SaveHosts(ctx, hosts)
	}
	return hosts, nil
}

func (s *ResolverConfigRuntimeStore) FakeDNS(ctx context.Context) (contractresolver.FakeDNS, error) {
	if s.Store != nil {
		return s.Store.FakeDNS(ctx)
	}
	return s.Runtime.FakeDNS(ctx)
}

func (s *ResolverConfigRuntimeStore) SaveFakeDNS(ctx context.Context, config contractresolver.FakeDNS) (contractresolver.FakeDNS, error) {
	if s.Runtime != nil {
		next, err := s.Runtime.SaveFakeDNS(ctx, config)
		if err != nil {
			return contractresolver.FakeDNS{}, err
		}
		config = next
	}
	if s.Store != nil {
		return s.Store.SaveFakeDNS(ctx, config)
	}
	return config, nil
}

func (s *ResolverConfigRuntimeStore) Server(ctx context.Context) (contractresolver.Server, error) {
	if s.Store != nil {
		return s.Store.Server(ctx)
	}
	return s.Runtime.Server(ctx)
}

func (s *ResolverConfigRuntimeStore) SaveServer(ctx context.Context, server contractresolver.Server) (contractresolver.Server, error) {
	if s.Runtime != nil {
		next, err := s.Runtime.SaveServer(ctx, server)
		if err != nil {
			return contractresolver.Server{}, err
		}
		server = next
	}
	if s.Store != nil {
		return s.Store.SaveServer(ctx, server)
	}
	return server, nil
}
