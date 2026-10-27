package main

import (
	"crypto/rand"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/latency"
)

const maxMeasurementBytes int64 = 64 << 20

func newMeasurementHandler(allowUpload bool) http.Handler {
	slots := make(chan struct{}, 2)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store, no-transform")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.URL.Path != "/download" && r.URL.Path != "/upload" {
			http.NotFound(w, r)
			return
		}
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			http.Error(w, "measurement concurrency limit reached", http.StatusTooManyRequests)
			return
		}
		if r.URL.Path == "/upload" {
			if !allowUpload {
				http.NotFound(w, r)
				return
			}
			serveUpload(w, r)
			return
		}
		serveDownload(w, r)
	})
}
func serveUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodHead && r.Method != http.MethodPost {
		w.Header().Set("Allow", "HEAD, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.Header.Get(latency.UploadProtocolHeader) != latency.UploadProtocolVersion || r.Header.Get("Content-Encoding") != "" {
		http.Error(w, "supported uncompressed upload handshake is required", http.StatusBadRequest)
		return
	}
	w.Header().Set(latency.UploadProtocolHeader, latency.UploadProtocolVersion)
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.ContentLength > maxMeasurementBytes {
		http.Error(w, "upload exceeds 64 MiB", http.StatusRequestEntityTooLarge)
		return
	}
	if r.Header.Get("Content-Type") != "application/octet-stream" {
		http.Error(w, "application/octet-stream is required", http.StatusUnsupportedMediaType)
		return
	}
	if err := http.NewResponseController(w).SetReadDeadline(time.Now().Add(15 * time.Second)); err != nil {
		http.Error(w, "cannot bound upload reads", http.StatusServiceUnavailable)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxMeasurementBytes)
	defer r.Body.Close()
	n, err := io.CopyBuffer(io.Discard, r.Body, make([]byte, 32<<10))
	if err != nil {
		if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
			http.Error(w, "upload exceeds 64 MiB", http.StatusRequestEntityTooLarge)
		} else {
			http.Error(w, "upload incomplete", http.StatusBadRequest)
		}
		return
	}
	if r.Context().Err() != nil {
		return
	}
	data, err := json.Marshal(latency.UploadAcknowledgement{Version: 1, ReceivedBytes: n})
	if err != nil {
		http.Error(w, "cannot acknowledge upload", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(data)
}
func serveDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	size, status := int64(4<<20), http.StatusOK
	if raw := r.Header.Get("Range"); raw != "" {
		end, err := strconv.ParseInt(strings.TrimPrefix(raw, "bytes=0-"), 10, 64)
		if err != nil || !strings.HasPrefix(raw, "bytes=0-") || end < 0 || end >= maxMeasurementBytes {
			w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", maxMeasurementBytes))
			http.Error(w, "bounded prefix range required", http.StatusRequestedRangeNotSatisfiable)
			return
		}
		size, status = end+1, http.StatusPartialContent
		w.Header().Set("Content-Range", fmt.Sprintf("bytes 0-%d/%d", end, maxMeasurementBytes))
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Accept-Ranges", "bytes")
	w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	if r.Method == http.MethodHead {
		w.WriteHeader(status)
		return
	}
	if err := http.NewResponseController(w).SetWriteDeadline(time.Now().Add(15 * time.Second)); err != nil {
		http.Error(w, "cannot bound download writes", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(status)
	_, _ = io.CopyBuffer(w, io.LimitReader(rand.Reader, size), make([]byte, 32<<10))
}
