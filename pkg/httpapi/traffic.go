package httpapi

import (
	"fmt"
	"net/http"

	"github.com/Asutorufa/yuhaiin/pkg/control"
)

func TrafficTotals(traffic control.Traffic) func(http.ResponseWriter, *http.Request) error {
	return func(w http.ResponseWriter, r *http.Request) error {
		total, err := traffic.Totals(r.Context())
		if err != nil {
			return err
		}

		return writeJSON(w, http.StatusOK, total)
	}
}

func TrafficEvents(traffic control.Traffic) func(http.ResponseWriter, *http.Request) error {
	return func(w http.ResponseWriter, r *http.Request) error {
		events, err := traffic.Watch(r.Context())
		if err != nil {
			return err
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")

		flusher, ok := w.(http.Flusher)
		if !ok {
			return writeError(w, http.StatusInternalServerError, "stream_unsupported", "http streaming is not supported")
		}

		for {
			select {
			case <-r.Context().Done():
				return r.Context().Err()
			case event, ok := <-events:
				if !ok {
					return nil
				}

				if _, err := fmt.Fprintf(w, "event: %s\n", event.Type); err != nil {
					return err
				}

				payload := event.Payload
				if len(payload) == 0 {
					payload = []byte("{}")
				}

				if _, err := w.Write([]byte("data: ")); err != nil {
					return err
				}
				if _, err := w.Write(payload); err != nil {
					return err
				}
				if _, err := w.Write([]byte("\n\n")); err != nil {
					return err
				}
				flusher.Flush()
			}
		}
	}
}
