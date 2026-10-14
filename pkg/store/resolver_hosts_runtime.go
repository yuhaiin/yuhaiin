package store

import (
	"context"
	"errors"

	contractresolver "github.com/Asutorufa/yuhaiin/pkg/contract/resolver"
)

func (s *ResolverConfigRuntimeStore) hostEntries(write bool) (contractresolver.HostEntries, error) {
	if write && s.Runtime != nil {
		if runtime, ok := s.Runtime.(contractresolver.HostEntries); ok {
			return runtime, nil
		}
		return nil, errors.New("host entry runtime is unavailable")
	}
	if s.Store != nil {
		return s.Store, nil
	}
	if runtime, ok := s.Runtime.(contractresolver.HostEntries); ok {
		return runtime, nil
	}
	return nil, errors.New("host entry store is unavailable")
}

func (s *ResolverConfigRuntimeStore) ListHostEntries(ctx context.Context, page, size int, query string) ([]contractresolver.HostEntry, int, error) {
	store, err := s.hostEntries(false)
	if err != nil {
		return nil, 0, err
	}
	return store.ListHostEntries(ctx, page, size, query)
}

func (s *ResolverConfigRuntimeStore) HostEntry(ctx context.Context, host string) (contractresolver.HostEntry, error) {
	store, err := s.hostEntries(false)
	if err != nil {
		return contractresolver.HostEntry{}, err
	}
	return store.HostEntry(ctx, host)
}

func (s *ResolverConfigRuntimeStore) SaveHostEntry(ctx context.Context, item contractresolver.HostEntry, create bool) (contractresolver.HostEntry, error) {
	store, err := s.hostEntries(true)
	if err != nil {
		return item, err
	}
	return store.SaveHostEntry(ctx, item, create)
}

func (s *ResolverConfigRuntimeStore) DeleteHostEntry(ctx context.Context, host string) error {
	store, err := s.hostEntries(true)
	if err != nil {
		return err
	}
	return store.DeleteHostEntry(ctx, host)
}
