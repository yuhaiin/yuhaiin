package node

import (
	"context"
	"crypto/x509"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/net/latency"
)

// A child process scopes a test-only root to this fixture on every platform.
// Production speed measurement keeps normal TLS verification.
func TestUploadRuntimeLocalTLS(t *testing.T) {
	if endpoint := os.Getenv("YUHAIIN_TEST_UPLOAD_ENDPOINT"); endpoint != "" {
		roots, err := os.ReadFile(os.Getenv("YUHAIIN_TEST_UPLOAD_ROOTS"))
		if err != nil {
			t.Fatal(err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(roots) {
			t.Fatal("invalid test roots")
		}
		x509.SetFallbackRoots(pool)
		r := newTestRuntime(t)
		if _, err := r.Save(t.Context(), testNode(t, "a", "a")); err != nil {
			t.Fatal(err)
		}
		request := contract.SpeedTestRequest{URL: endpoint, MaxBytes: 8192, DurationMS: 1000, TimeoutMS: 5000}
		for range 3 {
			request.Direction, request.AllowUpload = "download", false
			if m, err := r.Speed(t.Context(), "a", request); err != nil || !m.OK || m.DownloadMbps <= 0 || m.UploadMbps != 0 {
				t.Fatal(m, err)
			}
			request.Direction, request.AllowUpload = "upload", true
			if m, err := r.Speed(t.Context(), "a", request); err != nil || !m.OK || m.UploadMbps <= 0 || m.DownloadMbps != 0 {
				t.Fatal(m, err)
			}
		}
		original := r.observer.counter("a").snapshot()
		if original.Throughput.Samples != 3 || original.UploadThroughput.Samples != 3 || len(original.ThroughputHistory) != 6 {
			t.Fatal(original)
		}
		if err := r.Close(); err != nil {
			t.Fatal(err)
		}
		reopened := NewNodeRuntime(r.path)
		defer reopened.Close()
		statuses, err := reopened.Statuses(t.Context(), []string{"a"})
		if err != nil || len(statuses) != 1 || statuses[0].Throughput != original.Throughput || statuses[0].UploadThroughput != original.UploadThroughput || len(statuses[0].ThroughputHistory) != 6 {
			t.Fatal(statuses, err)
		}
		selector, err := NewSelectorService(reopened).Save(t.Context(), contract.Selector{Name: "Upload", NodeID: "a", Policy: &contract.SelectorPolicy{Mode: "balanced", UploadTarget: endpoint, Weights: contract.SelectorWeights{Upload: 1}, Candidates: []contract.SelectorCandidate{{NodeID: "a", Enabled: true, Weight: 1}}}})
		if err != nil {
			t.Fatal(err)
		}
		decision, err := NewSelectorService(reopened).Status(t.Context(), selector.ID)
		if err != nil || decision.TCP.NodeID != "a" || decision.TCP.Candidates[0].UploadSamples != 3 {
			t.Fatal(decision, err)
		}
		return
	}
	var posts atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(latency.UploadProtocolHeader, latency.UploadProtocolVersion)
		if r.Method == http.MethodHead {
			return
		}
		if r.Method == http.MethodGet {
			_, _ = w.Write(make([]byte, 8192))
			return
		}
		posts.Add(1)
		n, err := io.Copy(io.Discard, r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		data, _ := json.Marshal(latency.UploadAcknowledgement{Version: 1, ReceivedBytes: n})
		_, _ = w.Write(data)
	}))
	defer server.Close()
	cert := filepath.Join(t.TempDir(), "roots.pem")
	if err := os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestUploadRuntimeLocalTLS$", "-test.v")
	child.Env = append(os.Environ(), "YUHAIIN_TEST_UPLOAD_ENDPOINT="+server.URL, "YUHAIIN_TEST_UPLOAD_ROOTS="+cert, "GODEBUG="+os.Getenv("GODEBUG")+",x509usefallbackroots=1")
	if output, err := child.CombinedOutput(); err != nil {
		t.Fatalf("verified-TLS runtime test: %v\n%s", err, output)
	}
	if posts.Load() != 3 {
		t.Fatal("unexpected POST replay or missing upload", posts.Load())
	}
}
func TestUploadAndDownloadShareDurableDailyBudget(t *testing.T) {
	for _, first := range []string{"upload", "download"} {
		t.Run(first, func(t *testing.T) {
			r := newTestRuntime(t)
			if _, err := r.Save(t.Context(), testNode(t, "a", "a")); err != nil {
				t.Fatal(err)
			}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			endpoint := listener.Addr().String()
			_ = listener.Close()
			request := contract.SpeedTestRequest{URL: "https://" + endpoint, Direction: first, AllowUpload: true, MaxBytes: 1024, DurationMS: 100, TimeoutMS: 1000, DailyBudgetBytes: 1024 + contract.SpeedTransportAllowance}
			if _, err := r.Speed(t.Context(), "a", request); err == nil || errors.Is(err, errSpeedBudget) {
				t.Fatal("first reservation not spent", err)
			}
			if first == "upload" {
				request.Direction = "download"
			} else {
				request.Direction = "upload"
			}
			if _, err := r.Speed(t.Context(), "a", request); !errors.Is(err, errSpeedBudget) {
				t.Fatal("other direction reset allowance", err)
			}
			if err := r.Close(); err != nil {
				t.Fatal(err)
			}
			reopened := NewNodeRuntime(r.path)
			defer reopened.Close()
			if _, err := reopened.Speed(t.Context(), "a", request); !errors.Is(err, errSpeedBudget) {
				t.Fatal("restarting reset shared allowance", err)
			}
		})
	}
}
