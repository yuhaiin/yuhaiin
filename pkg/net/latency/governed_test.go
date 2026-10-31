package latency

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/inbound"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/trafficcontrol"
)

func governedTestProxy(t *testing.T, ctx context.Context, profile trafficcontrol.Profile) (netapi.Proxy, *inbound.Inbound) {
	t.Helper()
	in := inbound.NewInbound(netapi.NewErrProxy(errors.New("probe must not select another outbound")))
	t.Cleanup(func() { _ = in.Close() })
	if err := in.SetTrafficControl(trafficcontrol.Config{Enabled: true, Global: profile}); err != nil {
		t.Fatal(err)
	}
	p := in.ProbeProxy(ctx, new(measurementProxy), func(_ context.Context, a netapi.Address) (netapi.Address, error) { return a, nil })
	return p, in
}

func TestGovernedTLSUsesProbeLifetimeBeyondDialCancellation(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	defer server.Close()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	p, in := governedTestProxy(t, ctx, trafficcontrol.Profile{})
	// Explicit legacy insecure opt-in only for this local test CA. The active
	// throughput test below validates its chain with an explicit trusted root.
	if _, err := HTTPWithContext(ctx, p, server.URL, true); err != nil {
		t.Fatal("temporary dial cancellation killed established TLS", err)
	}
	if in.TrafficControlStatus().Global.Sessions != 0 {
		t.Fatal("HTTPS probe leaked admission")
	}
}

func TestDurationBudgetInterruptsLocallyPacedTLSDownload(t *testing.T) {
	payload := bytes.Repeat([]byte("a"), 64<<10)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(payload) }))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	p, in := governedTestProxy(t, t.Context(), trafficcontrol.Profile{Download: trafficcontrol.Rate{BytesPerSecond: 1, BurstBytes: 32768}})
	start := time.Now()
	m, err := measureDownload(t.Context(), p, contract.SpeedTestRequest{URL: server.URL, MaxBytes: 32768, DurationMS: 100, TimeoutMS: 1000}, &tls.Config{RootCAs: roots})
	if err != nil || !m.OK || m.Bytes < 1024 {
		t.Fatalf("paced duration truncation: %+v %v", m, err)
	}
	if time.Since(start) > 2*time.Second || m.DurationMS >= 1000 {
		t.Fatal("pacing escaped duration/timeout", m.DurationMS)
	}
	if in.TrafficControlStatus().Shaping.AdmittedDownloadBytes > 32770 {
		t.Fatal("download shaping was bypassed")
	}
	if in.TrafficControlStatus().Global.Sessions != 0 {
		t.Fatal("duration truncation leaked admission")
	}
}

func TestPacedHTTPRequestDeadlineIsNotRemoteFailure(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	defer server.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	p, _ := governedTestProxy(t, ctx, trafficcontrol.Profile{Upload: trafficcontrol.Rate{BytesPerSecond: 1, BurstBytes: 1}})
	_, err := HTTPWithContext(ctx, p, server.URL, true)
	if err == nil {
		t.Fatal("upload cap ignored")
	}
	classified := p.(interface{ ProbeError(error) error }).ProbeError(err)
	if !errors.Is(classified, trafficcontrol.ErrLocalLimit) {
		t.Fatal("HTTP lost local pacing classification", classified)
	}
}
