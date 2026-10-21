package store

import (
	"context"
	"errors"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/resolver"
)

func (s *ResolverConfigStore) ResponseRules(ctx context.Context) (contract.ResponseRules, error) {
	out := contract.ResponseRules{Rules: []contract.ResponseRule{}}
	if s == nil || s.db == nil {
		return out, errors.New("resolver config store database is nil")
	}
	err := NewSettingsStore(s.db).load(ctx, "dns", "response_rules", &out)
	return out, err
}

func (s *ResolverConfigStore) SaveResponseRules(ctx context.Context, config contract.ResponseRules) (contract.ResponseRules, error) {
	if err := config.Validate(); err != nil {
		return config, err
	}
	if s == nil || s.db == nil {
		return config, errors.New("resolver config store database is nil")
	}
	if config.Rules == nil {
		config.Rules = []contract.ResponseRule{}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return config, err
	}
	defer func() { _ = tx.Rollback() }()
	if err := saveSettingsKV(ctx, tx, "dns", "response_rules", config, time.Now().Unix()); err != nil {
		return config, err
	}
	return config, tx.Commit()
}

func (s *ResolverConfigRuntimeStore) ResponseRules(ctx context.Context) (contract.ResponseRules, error) {
	if s.Store != nil {
		return s.Store.ResponseRules(ctx)
	}
	if runtime, ok := s.Runtime.(contract.ResponseRulesController); ok {
		return runtime.ResponseRules(ctx)
	}
	return contract.ResponseRules{}, errors.New("DNS response rules are unavailable")
}

func (s *ResolverConfigRuntimeStore) SaveResponseRules(ctx context.Context, config contract.ResponseRules) (contract.ResponseRules, error) {
	if s.Runtime != nil {
		if runtime, ok := s.Runtime.(contract.ResponseRulesController); ok {
			return runtime.SaveResponseRules(ctx, config)
		}
		return config, errors.New("DNS response rules runtime is unavailable")
	}
	if s.Store != nil {
		return s.Store.SaveResponseRules(ctx, config)
	}
	return config, errors.New("DNS response rules store is unavailable")
}
