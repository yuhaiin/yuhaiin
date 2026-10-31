package main

import (
	"bytes"
	"encoding/json/v2"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/latency"
)

func TestExplicitHTTPSMeasurementEndpoint(t *testing.T) {
	server := httptest.NewTLSServer(newMeasurementHandler(true))
	defer server.Close()
	client := server.Client()
	head, _ := http.NewRequestWithContext(t.Context(), http.MethodHead, server.URL+"/upload", nil)
	head.Header.Set(latency.UploadProtocolHeader, latency.UploadProtocolVersion)
	response, err := client.Do(head)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNoContent || response.Header.Get(latency.UploadProtocolHeader) != latency.UploadProtocolVersion {
		t.Fatal(response.StatusCode, response.Header)
	}
	request, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+"/upload", strings.NewReader(strings.Repeat("x", 8192)))
	request.Header.Set(latency.UploadProtocolHeader, latency.UploadProtocolVersion)
	request.Header.Set("Content-Type", "application/octet-stream")
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, latency.MaxUploadAcknowledgementBytes+1))
	_ = response.Body.Close()
	var ack latency.UploadAcknowledgement
	if err != nil || response.StatusCode != http.StatusOK || json.Unmarshal(data, &ack) != nil || ack.Version != 1 || ack.ReceivedBytes != 8192 {
		t.Fatal(response.StatusCode, ack, err)
	}
	download, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"/download", nil)
	download.Header.Set("Range", "bytes=0-8191")
	response, err = client.Do(download)
	if err != nil {
		t.Fatal(err)
	}
	n, err := io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	if err != nil || response.StatusCode != http.StatusPartialContent || n != 8192 || response.Header.Get("Content-Range") != "bytes 0-8191/67108864" {
		t.Fatal(n, response.StatusCode, err)
	}
}
func TestMeasurementServerRejectsUnexpectedTraffic(t *testing.T) {
	for _, tc := range []struct {
		name, method, path, protocol, encoding, contentType, byteRange string
		upload                                                         bool
		expected                                                       int
	}{
		{name: "off_by_default", method: "HEAD", path: "/upload", expected: 404},
		{name: "missing_handshake", method: "POST", path: "/upload", upload: true, expected: 400},
		{name: "compressed", method: "POST", path: "/upload", upload: true, protocol: "1", encoding: "gzip", expected: 400},
		{name: "unsupported_media", method: "POST", path: "/upload", upload: true, protocol: "1", contentType: "application/json", expected: 415},
		{name: "upload_method", method: "PUT", path: "/upload", upload: true, expected: 405},
		{name: "download_method", method: "POST", path: "/download", expected: 405},
		{name: "bad_range", method: "GET", path: "/download", byteRange: "bytes=4-12", expected: 416},
		{name: "unbounded_range", method: "GET", path: "/download", byteRange: "bytes=0-67108864", expected: 416},
		{name: "unknown_path", method: "GET", path: "/other", expected: 404},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewTLSServer(newMeasurementHandler(tc.upload))
			defer server.Close()
			r, _ := http.NewRequestWithContext(t.Context(), tc.method, server.URL+tc.path, bytes.NewReader(nil))
			r.Header.Set(latency.UploadProtocolHeader, tc.protocol)
			r.Header.Set("Content-Encoding", tc.encoding)
			r.Header.Set("Content-Type", tc.contentType)
			r.Header.Set("Range", tc.byteRange)
			response, err := server.Client().Do(r)
			if err != nil {
				t.Fatal(err)
			}
			_ = response.Body.Close()
			if response.StatusCode != tc.expected {
				t.Fatal(response.StatusCode)
			}
		})
	}
}
