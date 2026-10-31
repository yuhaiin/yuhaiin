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
	if err == nil && r.Direction != "download" {
		err = errors.New("download measurement requires download direction")
	}
	if err != nil {
		return contract.ThroughputMeasurement{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(r.TimeoutMS)*time.Millisecond)
	defer cancel()
	timeoutCtx := ctx
	ctx, finish := context.WithCancelCause(ctx)
	defer finish(nil)
	result := contract.ThroughputMeasurement{At: time.Now().UnixMilli(), Target: r.URL, Direction: "download"}
	hc, closeClient := speedHTTPClient(ctx, p, tlsConfig)
	defer closeClient()
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
	readLimit, rangeLength := r.MaxBytes, int64(0)
	if response.StatusCode == http.StatusPartialContent {
		values := response.Header.Values("Content-Range")
		if len(values) != 1 {
			return result, errors.New("invalid speed test Content-Range")
		}
		end, ok := speedRangeEnd(values[0])
		if !ok || end >= r.MaxBytes || response.ContentLength >= 0 && response.ContentLength != end+1 {
			return result, errors.New("invalid speed test Content-Range")
		}
		rangeLength = end + 1
		// Read one extra byte when possible to detect a chunked response that
		// exceeds its declared range, without exceeding the measurement budget.
		readLimit = min(r.MaxBytes, rangeLength+1)
	}
	start := time.Now()
	// Cancel the I/O lifetime, not Body.Close (which can wait for a pending
	// read). The separate timeout context retains caller/whole-test failures.
	budget := time.AfterFunc(time.Duration(r.DurationMS)*time.Millisecond, func() { finish(errDownloadDuration) })
	defer budget.Stop()
	buffer := make([]byte, 32<<10)
	n, copyErr := io.CopyBuffer(io.Discard, io.LimitReader(response.Body, readLimit), buffer)
	budget.Stop()
	elapsed := time.Since(start)
	result.Bytes, result.DurationMS = n, elapsed.Milliseconds()
	if timeoutCtx.Err() != nil {
		return result, timeoutCtx.Err()
	}
	if copyErr != nil && !errors.Is(context.Cause(ctx), errDownloadDuration) {
		return result, copyErr
	}
	if rangeLength > 0 && (n > rangeLength || n < rangeLength && !errors.Is(context.Cause(ctx), errDownloadDuration)) {
		return result, errors.New("speed test response does not match Content-Range")
	}
	if n < 1024 || elapsed <= 0 {
		return result, errors.New("speed response too small for measurement")
	}
	result.OK, result.Samples = true, 1
	result.DownloadMbps = float64(n) * 8 / elapsed.Seconds() / 1e6
	return result, nil
}

// speedRangeEnd accepts only a single byte range starting at zero, with an
// unknown total or a decimal total strictly greater than the range end.
func speedRangeEnd(value string) (int64, bool) {
	value, ok := strings.CutPrefix(value, "bytes 0-")
	if !ok {
		return 0, false
	}
	span, total, ok := strings.Cut(value, "/")
	if !ok || !decimalDigits(span) {
		return 0, false
	}
	end, err := strconv.ParseInt(span, 10, 64)
	if err != nil {
		return 0, false
	}
	if total != "*" {
		if !decimalDigits(total) {
			return 0, false
		}
		// Compare canonical decimal strings so large valid totals cannot overflow.
		total = strings.TrimLeft(total, "0")
		endDecimal := strconv.FormatInt(end, 10)
		if len(total) < len(endDecimal) || len(total) == len(endDecimal) && total <= endDecimal {
			return 0, false
		}
	}
	return end, true
}

func decimalDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// Both directions bind every HTTP connection to the specified candidate and
// cancellation lifetime. No default proxy, redirect, TLS bypass or replay body.
func speedHTTPClient(ctx context.Context, p netapi.Proxy, tlsConfig *tls.Config) (*http.Client, func()) {
	connections := new(probeConnections)
	tr := &http.Transport{TLSClientConfig: tlsConfig, DisableCompression: true, DisableKeepAlives: true, MaxResponseHeaderBytes: 32 << 10, DialContext: func(dialCtx context.Context, network, address string) (net.Conn, error) {
		a, err := netapi.ParseAddress(network, address)
		if err != nil {
			return nil, err
		}
		c, err := p.Conn(dialCtx, a)
		if err != nil {
			return nil, err
		}
		return connections.bind(ctx, c)
	}}
	hc := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return hc, func() { tr.CloseIdleConnections(); connections.close() }
}
