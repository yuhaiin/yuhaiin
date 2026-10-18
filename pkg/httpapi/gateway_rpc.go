package httpapi

import (
	"context"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/gateway"
)

type GatewayController interface {
	Config() contract.Config
	Save(context.Context, contract.Config) (contract.Config, error)
	Test(contract.TestRequest) (contract.TestResult, error)
	Status() contract.RuntimeStatus
	CAStatus() contract.CAStatus
	GenerateCA(context.Context, uint64) (contract.CAStatus, error)
	ImportCA(context.Context, contract.CAImport) (contract.CAStatus, error)
	RefreshFilter(context.Context, string) (contract.Config, error)
}

type gatewayCARevisionRequest struct {
	Revision uint64 `json:"revision"`
}

func addGatewayRPCRoutesV2(handlers *v2Handlers, services V2Services) {
	addRPCRoute(handlers, v2GatewayFilterRefresh, func(ctx context.Context, r *idRequest) (*contract.Config, error) {
		if services.Gateway == nil {
			return nil, unavailable("gateway is unavailable")
		}
		v, err := services.Gateway.RefreshFilter(ctx, r.ID)
		if err != nil {
			return nil, badRequest(err)
		}
		return &v, nil
	})
	service := func() (GatewayController, error) {
		if services.Gateway == nil {
			return nil, unavailable("gateway is unavailable")
		}
		return services.Gateway, nil
	}
	addRPCRoute(handlers, v2GatewayConfigGet, func(_ context.Context, _ *emptyRequest) (*contract.Config, error) {
		s, err := service()
		if err != nil {
			return nil, err
		}
		return new(s.Config()), nil
	})
	addRPCRoute(handlers, v2GatewayConfigPut, func(ctx context.Context, r *contract.Config) (*contract.Config, error) {
		s, err := service()
		if err != nil {
			return nil, err
		}
		v, err := s.Save(ctx, *r)
		if err != nil {
			return nil, badRequest(err)
		}
		return &v, nil
	})
	addRPCRoute(handlers, v2GatewayStatus, func(_ context.Context, _ *emptyRequest) (*contract.RuntimeStatus, error) {
		s, err := service()
		if err != nil {
			return nil, err
		}
		return new(s.Status()), nil
	})
	addRPCRoute(handlers, v2GatewayTest, func(_ context.Context, r *contract.TestRequest) (*contract.TestResult, error) {
		s, err := service()
		if err != nil {
			return nil, err
		}
		v, err := s.Test(*r)
		if err != nil {
			return nil, badRequest(err)
		}
		return &v, nil
	})
	addRPCRoute(handlers, v2GatewayCAStatus, func(_ context.Context, _ *emptyRequest) (*contract.CAStatus, error) {
		s, err := service()
		if err != nil {
			return nil, err
		}
		return new(s.CAStatus()), nil
	})
	addRPCRoute(handlers, v2GatewayCAGenerate, func(ctx context.Context, r *gatewayCARevisionRequest) (*contract.CAStatus, error) {
		s, err := service()
		if err != nil {
			return nil, err
		}
		v, err := s.GenerateCA(ctx, r.Revision)
		if err != nil {
			return nil, badRequest(err)
		}
		return &v, nil
	})
	addRPCRoute(handlers, v2GatewayCAImport, func(ctx context.Context, r *contract.CAImport) (*contract.CAStatus, error) {
		s, err := service()
		if err != nil {
			return nil, err
		}
		v, err := s.ImportCA(ctx, *r)
		if err != nil {
			return nil, badRequest(err)
		}
		return &v, nil
	})
}
