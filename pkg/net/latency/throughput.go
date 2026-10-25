package latency

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

var errDownloadDuration = errors.New("download measurement duration reached")

// ValidateSpeedTest provides hard limits even for trusted administrators. The
// endpoint requires nodes:write; URL credentials, redirects and TLS bypass are
// not supported. A private target can only be chosen by that administrator.
func ValidateSpeedTest(r contract.SpeedTestRequest) (contract.SpeedTestRequest, error) {
	r = r.Effective()
	return r, r.Validate()
}

// MeasureDownload streams at most MaxBytes without loading the response into
// memory. Setup/headers are excluded from the payload window. Reaching the
// byte or duration budget is a successful normal truncation, not node failure.
// Compression and redirects are rejected to preserve a comparable target and
// exact byte accounting. Both 200 and a valid 206 range response are supported.
func MeasureDownload(ctx context.Context, p netapi.Proxy, request contract.SpeedTestRequest) (contract.ThroughputMeasurement, error) {
	return measureDownload(ctx, p, request, nil)
}

func measureDownload(ctx context.Context, p netapi.Proxy, request contract.SpeedTestRequest, tlsConfig *tls.Config) (contract.ThroughputMeasurement, error) {
	r, err := ValidateSpeedTest(request)
	if err != nil {
		return contract.ThroughputMeasurement{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(r.TimeoutMS)*time.Millisecond)
	defer cancel()
	timeoutCtx := ctx
	ctx, finish := context.WithCancelCause(ctx)
	defer finish(nil)
	probeCtx := ctx
	connections := new(probeConnections)
	defer connections.close()
	result := contract.ThroughputMeasurement{At: time.Now().UnixMilli(), Target: r.URL}
	tr := &http.Transport{TLSClientConfig: tlsConfig, DisableCompression: true, DisableKeepAlives: true, MaxResponseHeaderBytes: 32 << 10, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		a, err := netapi.ParseAddress(network, address)
		if err != nil {
			return nil, err
		}
		c, err := p.Conn(ctx, a)
		if err != nil {
			return nil, err
		}
		return connections.bind(probeCtx, c)
	}}
	defer tr.CloseIdleConnections()
	hc := &http.Client{Transport: tr, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.URL, nil)
	if err != nil {
		return result, err
	}
	req.Header.Set("Range", fmt.Sprintf("bytes=0-%d", r.MaxBytes-1))
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Cache-Control", "no-cache, no-store")
	req.Header.Set("Pragma", "no-cache")
	response, err := hc.Do(req)
	if err != nil {
		return result, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusPartialContent {
		return result, fmt.Errorf("speed endpoint returned HTTP %d", response.StatusCode)
	}
	if encoding := response.Header.Get("Content-Encoding"); encoding != "" && encoding != "identity" {
		return result, errors.New("speed endpoint returned compressed content")
	}
	if response.StatusCode == http.StatusPartialContent {
		value := response.Header.Get("Content-Range")
		span, _, ok := strings.Cut(strings.TrimPrefix(value, "bytes 0-"), "/")
		end, parseErr := strconv.ParseInt(span, 10, 64)
		if !strings.HasPrefix(value, "bytes 0-") || !ok || parseErr != nil || end < 0 || end >= r.MaxBytes || response.ContentLength > 0 && response.ContentLength != end+1 {
			return result, errors.New("invalid speed test Content-Range")
		}
	}
	start := time.Now()
	// Cancel the I/O lifetime, not Body.Close (which can wait for a pending
	// read). The separate timeout context retains caller/whole-test failures.
	budget := time.AfterFunc(time.Duration(r.DurationMS)*time.Millisecond, func() { finish(errDownloadDuration) })
	defer budget.Stop()
	buffer := make([]byte, 32<<10)
	n, copyErr := io.CopyBuffer(io.Discard, io.LimitReader(response.Body, r.MaxBytes), buffer)
	elapsed := time.Since(start)
	result.Bytes, result.DurationMS = n, elapsed.Milliseconds()
	if timeoutCtx.Err() != nil {
		return result, timeoutCtx.Err()
	}
	if copyErr != nil && !errors.Is(context.Cause(ctx), errDownloadDuration) {
		return result, copyErr
	}
	if n < 1024 || elapsed <= 0 {
		return result, errors.New("speed response too small for measurement")
	}
	result.OK, result.Samples = true, 1
	result.DownloadMbps = float64(n) * 8 / elapsed.Seconds() / 1e6
	return result, nil
}
