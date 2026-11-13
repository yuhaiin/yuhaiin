package httpapi

import (
	"context"

	contractsysnet "github.com/Asutorufa/yuhaiin/pkg/contract/sysnet"
)

// SystemNetworkController is the System Network Manager. The saved
// configuration and runtime status are separate resources: a successful save
// can still report an apply failure in its status.
type SystemNetworkController interface {
	Config(context.Context) (contractsysnet.Config, error)
	Save(context.Context, contractsysnet.Config) (contractsysnet.SaveResult, error)
	Status() contractsysnet.Status
	Interfaces(context.Context) (contractsysnet.Interfaces, error)
	Preview(context.Context, contractsysnet.Config) contractsysnet.Preview
}

func addSystemNetworkRPCRoutes(handlers *v2Handlers, services V2Services) {
	api := v2API{services: services}
	addRPCRoute(handlers, v2SystemNetworkConfigGet, api.systemNetworkConfig)
	addRPCRoute(handlers, v2SystemNetworkConfigPut, api.saveSystemNetwork)
	addRPCRoute(handlers, v2SystemNetworkStatus, api.systemNetworkStatus)
	addRPCRoute(handlers, v2SystemNetworkInterfaces, api.systemNetworkInterfaces)
	addRPCRoute(handlers, v2SystemNetworkPreview, api.previewSystemNetwork)
}

func (a v2API) systemNetwork() (SystemNetworkController, error) {
	if a.services.SystemNetwork == nil {
		return nil, unavailable("System Network is unavailable")
	}
	return a.services.SystemNetwork, nil
}

func (a v2API) systemNetworkConfig(ctx context.Context, _ *emptyRequest) (*contractsysnet.Config, error) {
	m, err := a.systemNetwork()
	if err != nil {
		return nil, err
	}
	config, err := m.Config(ctx)
	if err != nil {
		return nil, unavailable(err.Error())
	}
	return &config, nil
}

func (a v2API) saveSystemNetwork(ctx context.Context, request *contractsysnet.Config) (*contractsysnet.SaveResult, error) {
	m, err := a.systemNetwork()
	if err != nil {
		return nil, err
	}
	result, err := m.Save(ctx, *request)
	if err != nil {
		return nil, badRequest(err)
	}
	return &result, nil
}

func (a v2API) systemNetworkStatus(_ context.Context, _ *emptyRequest) (*contractsysnet.Status, error) {
	m, err := a.systemNetwork()
	if err != nil {
		return nil, err
	}
	status := m.Status()
	return &status, nil
}

func (a v2API) systemNetworkInterfaces(ctx context.Context, _ *emptyRequest) (*contractsysnet.Interfaces, error) {
	m, err := a.systemNetwork()
	if err != nil {
		return nil, err
	}
	list, err := m.Interfaces(ctx)
	if err != nil {
		return nil, unavailable(err.Error())
	}
	return &list, nil
}

func (a v2API) previewSystemNetwork(ctx context.Context, request *contractsysnet.Config) (*contractsysnet.Preview, error) {
	m, err := a.systemNetwork()
	if err != nil {
		return nil, err
	}
	preview := m.Preview(ctx, *request)
	return &preview, nil
}
