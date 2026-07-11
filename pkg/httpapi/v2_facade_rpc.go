package httpapi

import (
	"context"
	"errors"
	"time"

	contractbackup "github.com/Asutorufa/yuhaiin/pkg/contract/backup"
	contractconnection "github.com/Asutorufa/yuhaiin/pkg/contract/connection"
	contractresolver "github.com/Asutorufa/yuhaiin/pkg/contract/resolver"
	contractsettings "github.com/Asutorufa/yuhaiin/pkg/contract/settings"
	contracttools "github.com/Asutorufa/yuhaiin/pkg/contract/tools"
	contractupdate "github.com/Asutorufa/yuhaiin/pkg/contract/update"
)

type v2API struct{ services V2Services }

func addFacadeRPCRoutesV2(handlers *v2Handlers, services V2Services) {
	api := v2API{services: services}
	addRPCRoute(handlers, v2Info, api.info)
	addRPCRoute(handlers, v2UpdateCheck, api.updateCheck)
	addRPCRoute(handlers, v2UpdateApply, api.updateApply)
	addRPCRoute(handlers, v2UpdateStatus, api.updateStatus)
	addRPCRoute(handlers, v2SettingsGet, api.settings)
	addRPCRoute(handlers, v2SettingsPut, api.saveSettings)
	addRPCRoute(handlers, v2BackupConfigGet, api.backupConfig)
	addRPCRoute(handlers, v2BackupConfigPut, api.saveBackupConfig)
	addRPCRoute(handlers, v2BackupRun, api.runBackup)
	addRPCRoute(handlers, v2BackupRestore, api.restoreBackup)
	addRPCRoute(handlers, v2ToolsInterfaces, api.interfaces)
	addRPCRoute(handlers, v2ToolsLicenses, api.licenses)
	handlers.add(v2ToolsLogs, toolsLogsV2(services))
	handlers.add(v2ToolsLogsV2, toolsLogsV2(services))
	addRPCRoute(handlers, v2ConnectionsTotal, api.totalFlow)
	addRPCRoute(handlers, v2ConnectionsTraffic, api.traffic)
	addRPCRoute(handlers, v2ConnectionsTelemetry, api.telemetry)
	handlers.add(v2ConnectionsEvents, connectionsEventsV2(services))
	addRPCRoute(handlers, v2Connections, api.connections)
	addRPCRoute(handlers, v2ConnectionsClose, api.closeConnections)
	addRPCRoute(handlers, v2ConnectionsFailedHistory, api.failedHistory)
	addRPCRoute(handlers, v2ConnectionsHistory, api.allHistory)
	addRPCRoute(handlers, v2ResolverHostsGet, api.hosts)
	addRPCRoute(handlers, v2ResolverHostsPut, api.saveHosts)
	addRPCRoute(handlers, v2ResolverFakeDNSGet, api.fakeDNS)
	addRPCRoute(handlers, v2ResolverFakeDNSPut, api.saveFakeDNS)
	addRPCRoute(handlers, v2ResolverServerGet, api.resolverServer)
	addRPCRoute(handlers, v2ResolverServerPut, api.saveResolverServer)
}

func (a v2API) info(ctx context.Context, _ *emptyRequest) (*contractsettings.Info, error) {
	if a.services.Settings == nil {
		return nil, unavailable("settings controller is unavailable")
	}
	return pointer(a.services.Settings.Info(ctx))
}

func (a v2API) updateCheck(ctx context.Context, request *contractupdate.CheckRequest) (*contractupdate.CheckResult, error) {
	if a.services.Update == nil {
		return nil, unavailable("update controller is unavailable")
	}
	channel := request.Channel
	if channel == "" {
		channel = contractupdate.ChannelStable
		if request.IncludePrerelease {
			channel = contractupdate.ChannelBeta
		}
	}
	return pointer(a.services.Update.Check(ctx, channel))
}

func (a v2API) updateApply(ctx context.Context, request *contractupdate.ApplyRequest) (*emptyResponse, error) {
	if a.services.Update == nil {
		return nil, unavailable("update controller is unavailable")
	}
	if request.Channel == "" {
		request.Channel = contractupdate.ChannelStable
		if request.IncludePrerelease {
			request.Channel = contractupdate.ChannelBeta
		}
	}
	if err := a.services.Update.Apply(ctx, *request); err != nil {
		return nil, badRequest(err)
	}
	return &emptyResponse{}, nil
}

func (a v2API) updateStatus(ctx context.Context, _ *emptyRequest) (*contractupdate.Status, error) {
	if a.services.Update == nil {
		return nil, unavailable("update controller is unavailable")
	}
	status := a.services.Update.Status(ctx)
	return &status, nil
}
func (a v2API) settings(ctx context.Context, _ *emptyRequest) (*contractsettings.Settings, error) {
	if a.services.Settings == nil {
		return nil, unavailable("settings controller is unavailable")
	}
	return pointer(a.services.Settings.Load(ctx))
}
func (a v2API) saveSettings(ctx context.Context, request *contractsettings.Settings) (*contractsettings.Settings, error) {
	if a.services.Settings == nil {
		return nil, unavailable("settings controller is unavailable")
	}
	value, err := a.services.Settings.Save(ctx, *request)
	if err != nil {
		return nil, badRequest(err)
	}
	return &value, nil
}
func (a v2API) backupConfig(ctx context.Context, _ *emptyRequest) (*contractbackup.Option, error) {
	if a.services.Backup == nil {
		return nil, unavailable("backup controller is unavailable")
	}
	return pointer(a.services.Backup.Get(ctx))
}
func (a v2API) saveBackupConfig(ctx context.Context, request *contractbackup.Option) (*contractbackup.Option, error) {
	if a.services.Backup == nil {
		return nil, unavailable("backup controller is unavailable")
	}
	value, err := a.services.Backup.Save(ctx, *request)
	if err != nil {
		return nil, badRequest(err)
	}
	return &value, nil
}
func (a v2API) runBackup(ctx context.Context, _ *emptyRequest) (*emptyResponse, error) {
	if a.services.Backup == nil {
		return nil, unavailable("backup controller is unavailable")
	}
	if err := a.services.Backup.Run(ctx); err != nil {
		return nil, err
	}
	return &emptyResponse{}, nil
}
func (a v2API) restoreBackup(ctx context.Context, request *contractbackup.RestoreOption) (*emptyResponse, error) {
	if a.services.Backup == nil {
		return nil, unavailable("backup controller is unavailable")
	}
	if err := a.services.Backup.Restore(ctx, *request); err != nil {
		return nil, badRequest(err)
	}
	return &emptyResponse{}, nil
}
func (a v2API) interfaces(ctx context.Context, _ *emptyRequest) (*contracttools.Interfaces, error) {
	if a.services.Tools == nil {
		return nil, unavailable("tools controller is unavailable")
	}
	return pointer(a.services.Tools.Interfaces(ctx))
}
func (a v2API) licenses(ctx context.Context, _ *emptyRequest) (*contracttools.Licenses, error) {
	if a.services.Tools == nil {
		return nil, unavailable("tools controller is unavailable")
	}
	return pointer(a.services.Tools.Licenses(ctx))
}
func (a v2API) totalFlow(ctx context.Context, _ *emptyRequest) (*contractconnection.TotalFlow, error) {
	if a.services.Connections == nil {
		return nil, unavailable("connections controller is unavailable")
	}
	return pointer(a.services.Connections.Total(ctx))
}

type trafficRequest struct {
	Interval string `json:"interval"`
	From     string `json:"from"`
	To       string `json:"to"`
}

func (a v2API) traffic(ctx context.Context, request *trafficRequest) (*contractconnection.TrafficSeries, error) {
	if a.services.Connections == nil {
		return nil, unavailable("connections controller is unavailable")
	}
	interval := request.Interval
	if interval == "" {
		interval = "hour"
	}
	from, err := time.Parse(time.RFC3339, request.From)
	if err != nil {
		return nil, badRequest(errors.New("from must be an RFC3339 timestamp"))
	}
	to, err := time.Parse(time.RFC3339, request.To)
	if err != nil {
		return nil, badRequest(errors.New("to must be an RFC3339 timestamp"))
	}
	if !from.Before(to) {
		return nil, badRequest(errors.New("from must be before to"))
	}
	return pointer(a.services.Connections.Traffic(ctx, interval, from, to))
}

type telemetryRequest struct {
	From  string `json:"from"`
	To    string `json:"to"`
	Limit int    `json:"limit"`
}

func (a v2API) telemetry(ctx context.Context, request *telemetryRequest) (*contractconnection.TelemetrySummary, error) {
	if a.services.Connections == nil {
		return nil, unavailable("connections controller is unavailable")
	}
	from, err := time.Parse(time.RFC3339, request.From)
	if err != nil {
		return nil, badRequest(errors.New("from must be an RFC3339 timestamp"))
	}
	to, err := time.Parse(time.RFC3339, request.To)
	if err != nil {
		return nil, badRequest(errors.New("to must be an RFC3339 timestamp"))
	}
	if !from.Before(to) {
		return nil, badRequest(errors.New("from must be before to"))
	}
	limit := request.Limit
	if limit == 0 {
		limit = 8
	}
	if limit < 1 || limit > 50 {
		return nil, badRequest(errors.New("limit must be between 1 and 50"))
	}
	return pointer(a.services.Connections.Telemetry(ctx, from, to, limit))
}
func (a v2API) connections(ctx context.Context, _ *emptyRequest) (*contractconnection.Connections, error) {
	if a.services.Connections == nil {
		return nil, unavailable("connections controller is unavailable")
	}
	return pointer(a.services.Connections.List(ctx))
}
func (a v2API) closeConnections(ctx context.Context, request *contractconnection.CloseRequest) (*emptyResponse, error) {
	if a.services.Connections == nil {
		return nil, unavailable("connections controller is unavailable")
	}
	ids, err := parseUint64IDs(request.IDs)
	if err != nil {
		return nil, badRequest(err)
	}
	if err := a.services.Connections.Close(ctx, ids); err != nil {
		return nil, err
	}
	return &emptyResponse{}, nil
}
func (a v2API) failedHistory(ctx context.Context, _ *emptyRequest) (*contractconnection.FailedHistoryList, error) {
	if a.services.Connections == nil {
		return nil, unavailable("connections controller is unavailable")
	}
	return pointer(a.services.Connections.FailedHistory(ctx))
}
func (a v2API) allHistory(ctx context.Context, _ *emptyRequest) (*contractconnection.AllHistoryList, error) {
	if a.services.Connections == nil {
		return nil, unavailable("connections controller is unavailable")
	}
	return pointer(a.services.Connections.AllHistory(ctx))
}
func (a v2API) hosts(ctx context.Context, _ *emptyRequest) (*contractresolver.Hosts, error) {
	if a.services.ResolverConfig == nil {
		return nil, unavailable("resolver controller is unavailable")
	}
	return pointer(a.services.ResolverConfig.Hosts(ctx))
}
func (a v2API) saveHosts(ctx context.Context, request *contractresolver.Hosts) (*contractresolver.Hosts, error) {
	if a.services.ResolverConfig == nil {
		return nil, unavailable("resolver controller is unavailable")
	}
	value, err := a.services.ResolverConfig.SaveHosts(ctx, *request)
	if err != nil {
		return nil, badRequest(err)
	}
	return &value, nil
}
func (a v2API) fakeDNS(ctx context.Context, _ *emptyRequest) (*contractresolver.FakeDNS, error) {
	if a.services.ResolverConfig == nil {
		return nil, unavailable("resolver controller is unavailable")
	}
	return pointer(a.services.ResolverConfig.FakeDNS(ctx))
}
func (a v2API) saveFakeDNS(ctx context.Context, request *contractresolver.FakeDNS) (*contractresolver.FakeDNS, error) {
	if a.services.ResolverConfig == nil {
		return nil, unavailable("resolver controller is unavailable")
	}
	value, err := a.services.ResolverConfig.SaveFakeDNS(ctx, *request)
	if err != nil {
		return nil, badRequest(err)
	}
	return &value, nil
}
func (a v2API) resolverServer(ctx context.Context, _ *emptyRequest) (*contractresolver.Server, error) {
	if a.services.ResolverConfig == nil {
		return nil, unavailable("resolver controller is unavailable")
	}
	return pointer(a.services.ResolverConfig.Server(ctx))
}
func (a v2API) saveResolverServer(ctx context.Context, request *contractresolver.Server) (*contractresolver.Server, error) {
	if a.services.ResolverConfig == nil {
		return nil, unavailable("resolver controller is unavailable")
	}
	value, err := a.services.ResolverConfig.SaveServer(ctx, *request)
	if err != nil {
		return nil, badRequest(err)
	}
	return &value, nil
}

func pointer[T any](value T, err error) (*T, error) {
	if err != nil {
		return nil, err
	}
	return &value, nil
}
