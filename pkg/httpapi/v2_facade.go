package httpapi

import (
	json "encoding/json/v2"
	"fmt"
	"net/http"
	"strconv"

	contractconnection "github.com/Asutorufa/yuhaiin/pkg/contract/connection"
	contracttools "github.com/Asutorufa/yuhaiin/pkg/contract/tools"
)

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
	output := make([]uint64, 0, len(ids))
	for _, id := range ids {
		value, err := strconv.ParseUint(id, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid connection id %q", id)
		}
		output = append(output, value)
	}
	return output, nil
}
