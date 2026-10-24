package route

import (
	"context"
	"database/sql"
	"errors"

	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
)

type ContractListController struct {
	lists *Lists
}

func NewContractListController(lists *Lists) ContractListController {
	return ContractListController{lists: lists}
}

func (c ContractListController) Refresh(ctx context.Context) error {
	if c.lists == nil {
		return errors.New("list controller is unavailable")
	}
	return c.lists.RefreshContract(ctx)
}

func (c ContractListController) ApplyChanges(context.Context) error {
	if c.lists == nil {
		return errors.New("list controller is unavailable")
	}
	c.lists.ApplyListChanges()
	return nil
}

func (c ContractListController) Apply(context.Context) error {
	if c.lists == nil {
		return errors.New("list controller is unavailable")
	}
	return c.lists.ApplyListChangesNow()
}

func (c ContractListController) ActivationStatus(context.Context) (contractroute.ListActivationStatus, error) {
	if c.lists == nil {
		return contractroute.ListActivationStatus{}, errors.New("list controller is unavailable")
	}
	return c.lists.ActivationStatus(), nil
}

func (c ContractListController) GeoIPCountries(ctx context.Context) (contractroute.GeoIPCountries, error) {
	if err := ctx.Err(); err != nil {
		return contractroute.GeoIPCountries{}, err
	}
	if c.lists == nil {
		return contractroute.GeoIPCountries{}, errors.New("list controller is unavailable")
	}
	return c.lists.GeoIPCountries()
}

type ContractRuleController struct {
	rules *Rules
}

func NewContractRuleController(rules *Rules) ContractRuleController {
	return ContractRuleController{rules: rules}
}

func (c ContractRuleController) ScheduleApply() {
	if c.rules != nil {
		c.rules.ScheduleApply()
	}
}

func (c ContractRuleController) Apply(ctx context.Context) error {
	if c.rules == nil {
		return errors.New("rule controller is unavailable")
	}
	return c.rules.Apply(ctx)
}

func (c ContractRuleController) ActivationStatus(ctx context.Context) (contractroute.RuleActivationStatus, error) {
	if c.rules == nil {
		return contractroute.RuleActivationStatus{}, errors.New("rule controller is unavailable")
	}
	return c.rules.ActivationStatus(ctx)
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

func (c ContractRuleController) CommitConfiguration(ctx context.Context, tx *sql.Tx, validate bool) error {
	if c.rules == nil {
		return errors.New("rule controller is unavailable")
	}
	return c.rules.CommitConfiguration(ctx, tx, validate)
}

func (c ContractRuleController) WithConfiguration(ctx context.Context, apply func(context.Context) error) error {
	if c.rules == nil {
		return errors.New("rule controller is unavailable")
	}
	return c.rules.WithConfiguration(ctx, apply)
}

func (c ContractRuleController) PrefetchConfiguration(ctx context.Context, urls []string) error {
	if c.rules == nil {
		return errors.New("rule controller is unavailable")
	}
	return c.rules.PrefetchConfiguration(ctx, urls)
}
