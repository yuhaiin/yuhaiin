package latency

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

type measurementProxy struct {
	netapi.Proxy
	calls atomic.Int32
}

func (p *measurementProxy) Conn(ctx context.Context, a netapi.Address) (net.Conn, error) {
	p.calls.Add(1)
	return new(net.Dialer).DialContext(ctx, "tcp", a.String())
}

func TestThroughputUsesNodeAndBudgetsPayload(t *testing.T) {
	for _, rangeResponse := range []bool{false, true} {
		t.Run(fmt.Sprint(rangeResponse), func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Accept-Encoding") != "identity" || r.Header.Get("Range") != "bytes=0-8191" {
					t.Error("missing measurement headers", r.Header)
				}
				if rangeResponse {
					w.Header().Set("Content-Range", "bytes 0-8191/8192")
					w.WriteHeader(206)
				}
				_, _ = w.Write(bytes.Repeat([]byte{42}, 16384))
			}))
			defer server.Close()
			pool := x509.NewCertPool()
			pool.AddCert(server.Certificate())
			proxy := new(measurementProxy)
			m, err := measureDownload(t.Context(), proxy, contract.SpeedTestRequest{URL: server.URL, MaxBytes: 8192}, &tls.Config{RootCAs: pool})
			if err != nil || !m.OK || m.Bytes != 8192 || m.DownloadMbps <= 0 || proxy.calls.Load() != 1 {
				t.Fatalf("measurement=%+v, calls=%d, err=%v", m, proxy.calls.Load(), err)
			}
		})
	}
}

func TestThroughputTLSRedirectCompressionAndCancellation(t *testing.T) {
	for _, behavior := range []string{"untrusted", "redirect", "compressed", "bad_range", "cancel", "duration"} {
		t.Run(behavior, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch behavior {
				case "redirect":
					w.Header().Set("Location", "https://another.invalid/")
					w.WriteHeader(302)
				case "compressed":
					w.Header().Set("Content-Encoding", "gzip")
					_, _ = w.Write([]byte("compressed"))
				case "bad_range":
					w.Header().Set("Content-Range", "bytes 5-99/100")
					w.WriteHeader(206)
				case "cancel", "duration":
					_, _ = w.Write(bytes.Repeat([]byte{1}, 2048))
					w.(http.Flusher).Flush()
					<-r.Context().Done()
				default:
					_, _ = w.Write(bytes.Repeat([]byte{1}, 2048))
				}
			}))
			defer server.Close()
			pool := x509.NewCertPool()
			pool.AddCert(server.Certificate())
			config := &tls.Config{RootCAs: pool}
			if behavior == "untrusted" {
				config = nil
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if behavior == "cancel" {
				timer := time.AfterFunc(50*time.Millisecond, cancel)
				defer timer.Stop()
			}
			m, err := measureDownload(ctx, new(measurementProxy), contract.SpeedTestRequest{URL: server.URL, DurationMS: 100, TimeoutMS: 1000}, config)
			if behavior == "duration" {
				if err != nil || !m.OK || m.Bytes != 2048 {
					t.Fatal(m, err)
				}
			} else if err == nil || m.OK {
				t.Fatal("invalid response accepted", m, err)
			}
		})
	}
}

func TestThroughputLimitsCannotBeDisabled(t *testing.T) {
	for _, r := range []contract.SpeedTestRequest{{URL: "http://example.com"}, {URL: "https://user:secret@example.com"}, {URL: "https://example.com", MaxBytes: -1}, {URL: "https://example.com", MaxBytes: 65 << 20}, {URL: "https://example.com", DurationMS: 16000}, {URL: "https://example.com", DailyBudgetBytes: 2 << 30}} {
		if _, err := ValidateSpeedTest(r); err == nil {
			t.Fatal("accepted", r)
		}
	}
}
