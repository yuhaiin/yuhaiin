package httpapi

import (
	json "encoding/json/v2"
	"fmt"
	"net/http"
	"strconv"
	"time"

	contractbackup "github.com/Asutorufa/yuhaiin/pkg/contract/backup"
	contractconnection "github.com/Asutorufa/yuhaiin/pkg/contract/connection"
	contractresolver "github.com/Asutorufa/yuhaiin/pkg/contract/resolver"
	contractsettings "github.com/Asutorufa/yuhaiin/pkg/contract/settings"
	contracttools "github.com/Asutorufa/yuhaiin/pkg/contract/tools"
)

// registerV2Service centralizes unavailable-service handling for v2 controller
// routes. The typed helpers below build on it for the common read/write/action
// shapes.
func registerV2Service[Service any](register RegisterFunc, pattern string, service Service, unavailable string, handler func(Service, http.ResponseWriter, *http.Request) error) {
	register(pattern, withV2Service(service, unavailable, handler))
}

func registerV2Available(register RegisterFunc, pattern string, available bool, unavailable string, handler func(http.ResponseWriter, *http.Request) error) {
	register(pattern, func(w http.ResponseWriter, r *http.Request) error {
		if !available {
			return writeError(w, http.StatusServiceUnavailable, "unavailable", unavailable)
		}
		return handler(w, r)
	})
}

func withV2Service[Service any](service Service, unavailable string, handler func(Service, http.ResponseWriter, *http.Request) error) func(http.ResponseWriter, *http.Request) error {
	return func(w http.ResponseWriter, r *http.Request) error {
		if any(service) == nil {
			return writeError(w, http.StatusServiceUnavailable, "unavailable", unavailable)
		}
		return handler(service, w, r)
	}
}

// registerV2Get and registerV2Put cover the common controller facade shape:
// reject an unavailable service, then read or write a JSON value. Keeping the
// service type and request/response types generic makes each route declaration
// small without moving its controller call or HTTP semantics out of sight.
func registerV2Get[Service, Response any](register RegisterFunc, pattern string, service Service, unavailable string, get func(Service, *http.Request) (Response, error)) {
	registerV2Service(register, pattern, service, unavailable, func(service Service, w http.ResponseWriter, r *http.Request) error {
		response, err := get(service, r)
		if err != nil {
			return err
		}
		return writeJSON(w, http.StatusOK, response)
	})
}

func registerV2Put[Service, Request, Response any](register RegisterFunc, pattern string, service Service, unavailable string, save func(Service, *http.Request, Request) (Response, error)) {
	registerV2Service(register, pattern, service, unavailable, func(service Service, w http.ResponseWriter, r *http.Request) error {
		var request Request
		if err := readJSONBody(r, &request); err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		response, err := save(service, r, request)
		if err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		return writeJSON(w, http.StatusOK, response)
	})
}

func registerV2Action[Service any](register RegisterFunc, pattern string, service Service, unavailable string, status int, actionErrorStatus int, action func(Service, *http.Request) error) {
	registerV2Service(register, pattern, service, unavailable, func(service Service, w http.ResponseWriter, r *http.Request) error {
		if err := action(service, r); err != nil {
			if actionErrorStatus != 0 {
				return writeError(w, actionErrorStatus, "bad_request", err.Error())
			}
			return err
		}
		return writeJSON(w, status, nil)
	})
}

func registerSettingsV2(register RegisterFunc, services V2Services) {
	const unavailable = "settings controller is unavailable"
	registerV2Get(register, "GET /api/v2/info", services.Settings, unavailable, func(service SettingsController, r *http.Request) (contractsettings.Info, error) {
		return service.Info(r.Context())
	})
	registerV2Get(register, "GET /api/v2/settings", services.Settings, unavailable, func(service SettingsController, r *http.Request) (contractsettings.Settings, error) {
		return service.Load(r.Context())
	})
	registerV2Put(register, "PUT /api/v2/settings", services.Settings, unavailable, func(service SettingsController, r *http.Request, request contractsettings.Settings) (contractsettings.Settings, error) {
		return service.Save(r.Context(), request)
	})
}

func registerBackupV2(register RegisterFunc, services V2Services) {
	const unavailable = "backup controller is unavailable"
	registerV2Get(register, "GET /api/v2/backup/config", services.Backup, unavailable, func(service BackupController, r *http.Request) (contractbackup.Option, error) {
		return service.Get(r.Context())
	})
	registerV2Put(register, "PUT /api/v2/backup/config", services.Backup, unavailable, func(service BackupController, r *http.Request, request contractbackup.Option) (contractbackup.Option, error) {
		return service.Save(r.Context(), request)
	})
	registerV2Action(register, "POST /api/v2/backup/run", services.Backup, unavailable, http.StatusNoContent, 0, func(service BackupController, r *http.Request) error {
		return service.Run(r.Context())
	})
	registerV2Action(register, "POST /api/v2/backup/restore", services.Backup, unavailable, http.StatusNoContent, http.StatusBadRequest, func(service BackupController, r *http.Request) error {
		var request contractbackup.RestoreOption
		if err := readJSONBody(r, &request); err != nil {
			return err
		}
		return service.Restore(r.Context(), request)
	})
}

func registerToolsV2(register RegisterFunc, services V2Services) {
	const unavailable = "tools controller is unavailable"
	registerV2Get(register, "GET /api/v2/tools/interfaces", services.Tools, unavailable, func(service ToolsController, r *http.Request) (contracttools.Interfaces, error) {
		return service.Interfaces(r.Context())
	})
	registerV2Get(register, "GET /api/v2/tools/licenses", services.Tools, unavailable, func(service ToolsController, r *http.Request) (contracttools.Licenses, error) {
		return service.Licenses(r.Context())
	})

	logs := toolsLogsV2(services)
	register("GET /api/v2/tools/logs", logs)
	register("GET /api/v2/tools/logs/v2", logs)
}

func registerConnectionsV2(register RegisterFunc, services V2Services) {
	const unavailable = "connections controller is unavailable"
	registerV2Get(register, "GET /api/v2/connections/total", services.Connections, unavailable, func(service ConnectionMonitor, r *http.Request) (contractconnection.TotalFlow, error) {
		return service.Total(r.Context())
	})

	registerV2Service(register, "GET /api/v2/connections/traffic", services.Connections, unavailable, func(service ConnectionMonitor, w http.ResponseWriter, r *http.Request) error {
		interval := r.URL.Query().Get("interval")
		if interval == "" {
			interval = "hour"
		}
		from, err := time.Parse(time.RFC3339, r.URL.Query().Get("from"))
		if err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", "from must be an RFC3339 timestamp")
		}
		to, err := time.Parse(time.RFC3339, r.URL.Query().Get("to"))
		if err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", "to must be an RFC3339 timestamp")
		}
		if !from.Before(to) {
			return writeError(w, http.StatusBadRequest, "bad_request", "from must be before to")
		}
		series, err := service.Traffic(r.Context(), interval, from, to)
		if err != nil {
			return err
		}
		return writeJSON(w, http.StatusOK, series)
	})

	registerV2Service(register, "GET /api/v2/connections/telemetry", services.Connections, unavailable, func(service ConnectionMonitor, w http.ResponseWriter, r *http.Request) error {
		from, err := time.Parse(time.RFC3339, r.URL.Query().Get("from"))
		if err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", "from must be an RFC3339 timestamp")
		}
		to, err := time.Parse(time.RFC3339, r.URL.Query().Get("to"))
		if err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", "to must be an RFC3339 timestamp")
		}
		if !from.Before(to) {
			return writeError(w, http.StatusBadRequest, "bad_request", "from must be before to")
		}
		limit := 8
		if raw := r.URL.Query().Get("limit"); raw != "" {
			limit, err = strconv.Atoi(raw)
			if err != nil || limit < 1 || limit > 50 {
				return writeError(w, http.StatusBadRequest, "bad_request", "limit must be between 1 and 50")
			}
		}
		summary, err := service.Telemetry(r.Context(), from, to, limit)
		if err != nil {
			return err
		}
		return writeJSON(w, http.StatusOK, summary)
	})

	register("GET /api/v2/connections/events", connectionsEventsV2(services))
	registerV2Get(register, "GET /api/v2/connections", services.Connections, unavailable, func(service ConnectionMonitor, r *http.Request) (contractconnection.Connections, error) {
		return service.List(r.Context())
	})
	registerV2Service(register, "POST /api/v2/connections/close", services.Connections, unavailable, func(service ConnectionMonitor, w http.ResponseWriter, r *http.Request) error {
		var req contractconnection.CloseRequest
		if err := readJSONBody(r, &req); err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		ids, err := parseUint64IDs(req.IDs)
		if err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		if err := service.Close(r.Context(), ids); err != nil {
			return err
		}
		return writeJSON(w, http.StatusNoContent, nil)
	})
	registerV2Get(register, "GET /api/v2/connections/failed-history", services.Connections, unavailable, func(service ConnectionMonitor, r *http.Request) (contractconnection.FailedHistoryList, error) {
		return service.FailedHistory(r.Context())
	})
	registerV2Get(register, "GET /api/v2/connections/history", services.Connections, unavailable, func(service ConnectionMonitor, r *http.Request) (contractconnection.AllHistoryList, error) {
		return service.AllHistory(r.Context())
	})
}

func registerResolverConfigV2(register RegisterFunc, services V2Services) {
	const unavailable = "resolver controller is unavailable"
	registerV2Get(register, "GET /api/v2/resolver/hosts", services.ResolverConfig, unavailable, func(service ResolverConfigController, r *http.Request) (contractresolver.Hosts, error) {
		return service.Hosts(r.Context())
	})
	registerV2Put(register, "PUT /api/v2/resolver/hosts", services.ResolverConfig, unavailable, func(service ResolverConfigController, r *http.Request, request contractresolver.Hosts) (contractresolver.Hosts, error) {
		return service.SaveHosts(r.Context(), request)
	})
	registerV2Get(register, "GET /api/v2/resolver/fakedns", services.ResolverConfig, unavailable, func(service ResolverConfigController, r *http.Request) (contractresolver.FakeDNS, error) {
		return service.FakeDNS(r.Context())
	})
	registerV2Put(register, "PUT /api/v2/resolver/fakedns", services.ResolverConfig, unavailable, func(service ResolverConfigController, r *http.Request, request contractresolver.FakeDNS) (contractresolver.FakeDNS, error) {
		return service.SaveFakeDNS(r.Context(), request)
	})
	registerV2Get(register, "GET /api/v2/resolver/server", services.ResolverConfig, unavailable, func(service ResolverConfigController, r *http.Request) (contractresolver.Server, error) {
		return service.Server(r.Context())
	})
	registerV2Put(register, "PUT /api/v2/resolver/server", services.ResolverConfig, unavailable, func(service ResolverConfigController, r *http.Request, request contractresolver.Server) (contractresolver.Server, error) {
		return service.SaveServer(r.Context(), request)
	})
}

func toolsLogsV2(services V2Services) func(http.ResponseWriter, *http.Request) error {
	return withV2Service(services.Tools, "tools controller is unavailable", func(service ToolsController, w http.ResponseWriter, r *http.Request) error {
		flusher, ok := w.(http.Flusher)
		if !ok {
			return writeError(w, http.StatusInternalServerError, "stream_unsupported", "http streaming is not supported")
		}
		writeSSEHeaders(w)
		return service.TailLogs(r.Context(), func(batch contracttools.LogBatch) error {
			return writeSSEJSON(w, flusher, "log", batch)
		})
	})
}

func connectionsEventsV2(services V2Services) func(http.ResponseWriter, *http.Request) error {
	return withV2Service(services.Connections, "connections controller is unavailable", func(service ConnectionMonitor, w http.ResponseWriter, r *http.Request) error {
		flusher, ok := w.(http.Flusher)
		if !ok {
			return writeError(w, http.StatusInternalServerError, "stream_unsupported", "http streaming is not supported")
		}
		writeSSEHeaders(w)
		return service.Events(r.Context(), func(event contractconnection.Event) error {
			return writeSSEJSON(w, flusher, event.Type, event.Payload)
		})
	})
}

func writeSSEHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
}

func writeSSEJSON(w http.ResponseWriter, flusher http.Flusher, event string, payload any) error {
	if _, err := fmt.Fprintf(w, "event: %s\n", event); err != nil {
		return err
	}
	if _, err := w.Write([]byte("data: ")); err != nil {
		return err
	}
	if payload == nil {
		payload = struct{}{}
	}
	if err := json.MarshalWrite(w, payload); err != nil {
		return err
	}
	if _, err := w.Write([]byte("\n\n")); err != nil {
		return err
	}
	flusher.Flush()
	return nil
}

func parseUint64IDs(ids []string) ([]uint64, error) {
	out := make([]uint64, 0, len(ids))
	for _, id := range ids {
		value, err := strconv.ParseUint(id, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid connection id %q", id)
		}
		out = append(out, value)
	}
	return out, nil
}
