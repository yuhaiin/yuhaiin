package route

import (
	"context"
	"errors"

	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
)

type ContractListController struct {
	lists *Lists
}

func NewContractListController(lists *Lists) ContractListController {
	return ContractListController{lists: lists}
}

func (c ContractListController) SaveConfig(ctx context.Context, config contractroute.ListConfig, refreshInterval uint64) error {
	if c.lists == nil {
		return errors.New("list controller is unavailable")
	}
	return c.lists.SaveContractConfig(ctx, config, refreshInterval)
}

func (c ContractListController) Refresh(ctx context.Context) error {
	if c.lists == nil {
		return errors.New("list controller is unavailable")
	}
	return c.lists.RefreshContract(ctx)
}

type ContractRuleController struct {
	rules *Rules
}

func NewContractRuleController(rules *Rules) ContractRuleController {
	return ContractRuleController{rules: rules}
}

func (c ContractRuleController) SaveConfig(ctx context.Context, config contractroute.Config) error {
	if c.rules == nil {
		return errors.New("rule controller is unavailable")
	}
	return c.rules.SaveContractConfig(ctx, config)
}

func (c ContractRuleController) Test(ctx context.Context, host string) (contractroute.RuleTestResponse, error) {
	if c.rules == nil {
		return contractroute.RuleTestResponse{}, errors.New("rule controller is unavailable")
	}
	return c.rules.TestContract(ctx, host)
}

func (c ContractRuleController) BlockHistory(ctx context.Context) (contractroute.BlockHistoryList, error) {
	if c.rules == nil {
		return contractroute.BlockHistoryList{}, errors.New("rule controller is unavailable")
	}
	return c.rules.BlockHistoryContract(ctx)
}
