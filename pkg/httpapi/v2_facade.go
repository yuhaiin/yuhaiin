package httpapi

import (
	json "encoding/json/v2"
	"fmt"
	"net/http"
	"strconv"

	contractbackup "github.com/Asutorufa/yuhaiin/pkg/contract/backup"
	contractconnection "github.com/Asutorufa/yuhaiin/pkg/contract/connection"
	contractresolver "github.com/Asutorufa/yuhaiin/pkg/contract/resolver"
	contractsettings "github.com/Asutorufa/yuhaiin/pkg/contract/settings"
	contracttools "github.com/Asutorufa/yuhaiin/pkg/contract/tools"
)

func registerSettingsV2(register RegisterFunc, services V2Services) {
	register("GET /api/v2/info", func(w http.ResponseWriter, r *http.Request) error {
		if services.Settings == nil {
			return writeError(w, http.StatusServiceUnavailable, "unavailable", "settings controller is unavailable")
		}
		info, err := services.Settings.Info(r.Context())
		if err != nil {
			return err
		}
		return writeJSON(w, http.StatusOK, info)
	})

	register("GET /api/v2/settings", func(w http.ResponseWriter, r *http.Request) error {
		if services.Settings == nil {
			return writeError(w, http.StatusServiceUnavailable, "unavailable", "settings controller is unavailable")
		}
		setting, err := services.Settings.Load(r.Context())
		if err != nil {
			return err
		}
		return writeJSON(w, http.StatusOK, setting)
	})

	register("PUT /api/v2/settings", func(w http.ResponseWriter, r *http.Request) error {
		if services.Settings == nil {
			return writeError(w, http.StatusServiceUnavailable, "unavailable", "settings controller is unavailable")
		}
		var req contractsettings.Settings
		if err := readJSONBody(r, &req); err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		next, err := services.Settings.Save(r.Context(), req)
		if err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		return writeJSON(w, http.StatusOK, next)
	})
}

func registerBackupV2(register RegisterFunc, services V2Services) {
	register("GET /api/v2/backup/config", func(w http.ResponseWriter, r *http.Request) error {
		if services.Backup == nil {
			return writeError(w, http.StatusServiceUnavailable, "unavailable", "backup controller is unavailable")
		}
		option, err := services.Backup.Get(r.Context())
		if err != nil {
			return err
		}
		return writeJSON(w, http.StatusOK, option)
	})

	register("PUT /api/v2/backup/config", func(w http.ResponseWriter, r *http.Request) error {
		if services.Backup == nil {
			return writeError(w, http.StatusServiceUnavailable, "unavailable", "backup controller is unavailable")
		}
		var req contractbackup.Option
		if err := readJSONBody(r, &req); err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		option, err := services.Backup.Save(r.Context(), req)
		if err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		return writeJSON(w, http.StatusOK, option)
	})

	register("POST /api/v2/backup/run", func(w http.ResponseWriter, r *http.Request) error {
		if services.Backup == nil {
			return writeError(w, http.StatusServiceUnavailable, "unavailable", "backup controller is unavailable")
		}
		if err := services.Backup.Run(r.Context()); err != nil {
			return err
		}
		return writeJSON(w, http.StatusNoContent, nil)
	})

	register("POST /api/v2/backup/restore", func(w http.ResponseWriter, r *http.Request) error {
		if services.Backup == nil {
			return writeError(w, http.StatusServiceUnavailable, "unavailable", "backup controller is unavailable")
		}
		var req contractbackup.RestoreOption
		if err := readJSONBody(r, &req); err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		if err := services.Backup.Restore(r.Context(), req); err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		return writeJSON(w, http.StatusNoContent, nil)
	})
}

func registerToolsV2(register RegisterFunc, services V2Services) {
	register("GET /api/v2/tools/interfaces", func(w http.ResponseWriter, r *http.Request) error {
		if services.Tools == nil {
			return writeError(w, http.StatusServiceUnavailable, "unavailable", "tools controller is unavailable")
		}
		ifaces, err := services.Tools.Interfaces(r.Context())
		if err != nil {
			return err
		}
		return writeJSON(w, http.StatusOK, ifaces)
	})

	register("GET /api/v2/tools/licenses", func(w http.ResponseWriter, r *http.Request) error {
		if services.Tools == nil {
			return writeError(w, http.StatusServiceUnavailable, "unavailable", "tools controller is unavailable")
		}
		licenses, err := services.Tools.Licenses(r.Context())
		if err != nil {
			return err
		}
		return writeJSON(w, http.StatusOK, licenses)
	})

	logs := toolsLogsV2(services)
	register("GET /api/v2/tools/logs", logs)
	register("GET /api/v2/tools/logs/v2", logs)
}

func registerConnectionsV2(register RegisterFunc, services V2Services) {
	register("GET /api/v2/connections/total", func(w http.ResponseWriter, r *http.Request) error {
		if services.Connections == nil {
			return writeError(w, http.StatusServiceUnavailable, "unavailable", "connections controller is unavailable")
		}
		total, err := services.Connections.Total(r.Context())
		if err != nil {
			return err
		}
		return writeJSON(w, http.StatusOK, total)
	})

	register("GET /api/v2/connections/events", connectionsEventsV2(services))

	register("GET /api/v2/connections", func(w http.ResponseWriter, r *http.Request) error {
		if services.Connections == nil {
			return writeError(w, http.StatusServiceUnavailable, "unavailable", "connections controller is unavailable")
		}
		conns, err := services.Connections.List(r.Context())
		if err != nil {
			return err
		}
		return writeJSON(w, http.StatusOK, conns)
	})

	register("POST /api/v2/connections/close", func(w http.ResponseWriter, r *http.Request) error {
		if services.Connections == nil {
			return writeError(w, http.StatusServiceUnavailable, "unavailable", "connections controller is unavailable")
		}
		var req contractconnection.CloseRequest
		if err := readJSONBody(r, &req); err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		ids, err := parseUint64IDs(req.IDs)
		if err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		if err := services.Connections.Close(r.Context(), ids); err != nil {
			return err
		}
		return writeJSON(w, http.StatusNoContent, nil)
	})

	register("GET /api/v2/connections/failed-history", func(w http.ResponseWriter, r *http.Request) error {
		if services.Connections == nil {
			return writeError(w, http.StatusServiceUnavailable, "unavailable", "connections controller is unavailable")
		}
		history, err := services.Connections.FailedHistory(r.Context())
		if err != nil {
			return err
		}
		return writeJSON(w, http.StatusOK, history)
	})

	register("GET /api/v2/connections/history", func(w http.ResponseWriter, r *http.Request) error {
		if services.Connections == nil {
			return writeError(w, http.StatusServiceUnavailable, "unavailable", "connections controller is unavailable")
		}
		history, err := services.Connections.AllHistory(r.Context())
		if err != nil {
			return err
		}
		return writeJSON(w, http.StatusOK, history)
	})
}

func registerResolverConfigV2(register RegisterFunc, services V2Services) {
	register("GET /api/v2/resolver/hosts", func(w http.ResponseWriter, r *http.Request) error {
		if services.ResolverConfig == nil {
			return writeError(w, http.StatusServiceUnavailable, "unavailable", "resolver controller is unavailable")
		}
		hosts, err := services.ResolverConfig.Hosts(r.Context())
		if err != nil {
			return err
		}
		return writeJSON(w, http.StatusOK, hosts)
	})

	register("PUT /api/v2/resolver/hosts", func(w http.ResponseWriter, r *http.Request) error {
		if services.ResolverConfig == nil {
			return writeError(w, http.StatusServiceUnavailable, "unavailable", "resolver controller is unavailable")
		}
		var req contractresolver.Hosts
		if err := readJSONBody(r, &req); err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		hosts, err := services.ResolverConfig.SaveHosts(r.Context(), req)
		if err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		return writeJSON(w, http.StatusOK, hosts)
	})

	register("GET /api/v2/resolver/fakedns", func(w http.ResponseWriter, r *http.Request) error {
		if services.ResolverConfig == nil {
			return writeError(w, http.StatusServiceUnavailable, "unavailable", "resolver controller is unavailable")
		}
		config, err := services.ResolverConfig.FakeDNS(r.Context())
		if err != nil {
			return err
		}
		return writeJSON(w, http.StatusOK, config)
	})

	register("PUT /api/v2/resolver/fakedns", func(w http.ResponseWriter, r *http.Request) error {
		if services.ResolverConfig == nil {
			return writeError(w, http.StatusServiceUnavailable, "unavailable", "resolver controller is unavailable")
		}
		var req contractresolver.FakeDNS
		if err := readJSONBody(r, &req); err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		config, err := services.ResolverConfig.SaveFakeDNS(r.Context(), req)
		if err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		return writeJSON(w, http.StatusOK, config)
	})

	register("GET /api/v2/resolver/server", func(w http.ResponseWriter, r *http.Request) error {
		if services.ResolverConfig == nil {
			return writeError(w, http.StatusServiceUnavailable, "unavailable", "resolver controller is unavailable")
		}
		server, err := services.ResolverConfig.Server(r.Context())
		if err != nil {
			return err
		}
		return writeJSON(w, http.StatusOK, server)
	})

	register("PUT /api/v2/resolver/server", func(w http.ResponseWriter, r *http.Request) error {
		if services.ResolverConfig == nil {
			return writeError(w, http.StatusServiceUnavailable, "unavailable", "resolver controller is unavailable")
		}
		var req contractresolver.Server
		if err := readJSONBody(r, &req); err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		server, err := services.ResolverConfig.SaveServer(r.Context(), req)
		if err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		return writeJSON(w, http.StatusOK, server)
	})
}

func toolsLogsV2(services V2Services) func(http.ResponseWriter, *http.Request) error {
	return func(w http.ResponseWriter, r *http.Request) error {
		if services.Tools == nil {
			return writeError(w, http.StatusServiceUnavailable, "unavailable", "tools controller is unavailable")
		}
		flusher, ok := w.(http.Flusher)
		if !ok {
			return writeError(w, http.StatusInternalServerError, "stream_unsupported", "http streaming is not supported")
		}
		writeSSEHeaders(w)
		return services.Tools.TailLogs(r.Context(), func(batch contracttools.LogBatch) error {
			return writeSSEJSON(w, flusher, "log", batch)
		})
	}
}

func connectionsEventsV2(services V2Services) func(http.ResponseWriter, *http.Request) error {
	return func(w http.ResponseWriter, r *http.Request) error {
		if services.Connections == nil {
			return writeError(w, http.StatusServiceUnavailable, "unavailable", "connections controller is unavailable")
		}
		flusher, ok := w.(http.Flusher)
		if !ok {
			return writeError(w, http.StatusInternalServerError, "stream_unsupported", "http streaming is not supported")
		}
		writeSSEHeaders(w)
		return services.Connections.Events(r.Context(), func(event contractconnection.Event) error {
			return writeSSEJSON(w, flusher, event.Type, event.Payload)
		})
	}
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
