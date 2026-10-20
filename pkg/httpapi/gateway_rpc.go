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
	ResetStatistics(context.Context, string) error
	CAStatus() contract.CAStatus
	GenerateCA(context.Context, uint64) (contract.CAStatus, error)
	ImportCA(context.Context, contract.CAImport) (contract.CAStatus, error)
	RefreshFilter(context.Context, string) (contract.Config, error)
}

type gatewayCARevisionRequest struct {
	Revision uint64 `json:"revision"`
}

func addGatewayRPCRoutesV2(handlers *v2Handlers, services V2Services) {
	addRPCRoute(handlers, v2GatewayFilterRefresh, func(ctx context.Context, r *idRequest) (*contract.Workspace, error) {
		if services.Gateway == nil {
			return nil, unavailable("gateway is unavailable")
		}
		v, err := services.Gateway.RefreshFilter(ctx, r.ID)
		if err != nil {
			return nil, badRequest(err)
		}
		workspace, err := contract.WorkspaceFromConfig(v)
		if err != nil {
			return nil, badRequest(err)
		}
		return &workspace, nil
	})
	service := func() (GatewayController, error) {
		if services.Gateway == nil {
			return nil, unavailable("gateway is unavailable")
		}
		return services.Gateway, nil
	}
	addRPCRoute(handlers, v2GatewayWorkspaceGet, func(_ context.Context, _ *emptyRequest) (*contract.Workspace, error) {
		s, err := service()
		if err != nil {
			return nil, err
		}
		workspace, err := contract.WorkspaceFromConfig(s.Config())
		if err != nil {
			return nil, badRequest(err)
		}
		return &workspace, nil
	})
	addRPCRoute(handlers, v2GatewayWorkspacePut, func(ctx context.Context, r *contract.Workspace) (*contract.Workspace, error) {
		s, err := service()
		if err != nil {
			return nil, err
		}
		config, err := contract.ConfigFromWorkspace(*r)
		if err != nil {
			return nil, badRequest(err)
		}
		saved, err := s.Save(ctx, config)
		if err != nil {
			return nil, badRequest(err)
		}
		workspace, err := contract.WorkspaceFromConfig(saved)
		if err != nil {
			return nil, badRequest(err)
		}
		return &workspace, nil
	})
	addRPCRoute(handlers, v2GatewayStatus, func(_ context.Context, _ *emptyRequest) (*contract.RuntimeStatus, error) {
		s, err := service()
		if err != nil {
			return nil, err
		}
		return new(s.Status()), nil
	})
	addRPCRoute(handlers, v2GatewayStatisticsReset, func(ctx context.Context, r *idRequest) (*emptyResponse, error) {
		s, err := service()
		if err != nil {
			return nil, err
		}
		if err := s.ResetStatistics(ctx, r.ID); err != nil {
			return nil, badRequest(err)
		}
		return new(emptyResponse), nil
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
