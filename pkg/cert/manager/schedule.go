package manager

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/cert/manager/dnschallenge"
	contract "github.com/Asutorufa/yuhaiin/pkg/contract/certificate"
	"golang.org/x/crypto/acme"
)

// RenewalWindow is a CA-supplied suggested window, when supported. Without one,
// renewal happens near two thirds of lifetime with stable per-certificate jitter.
type RenewalWindow struct{ Start, End time.Time }

func renewalTime(id, serial string, notBefore, notAfter time.Time, window RenewalWindow) time.Time {
	lifetime := notAfter.Sub(notBefore)
	if lifetime <= 0 {
		return time.Time{}
	}
	start, end := window.Start, window.End
	if start.IsZero() || !end.After(start) || start.Before(notBefore) || !end.Before(notAfter) {
		start = notBefore.Add(lifetime / 5 * 3)
		end = notBefore.Add(lifetime / 4 * 3)
	}
	hash := sha256.Sum256([]byte(id + ":" + serial))
	width := end.Sub(start)
	if width <= 0 {
		return notBefore.Add(lifetime / 2)
	}
	return start.Add(time.Duration(binary.BigEndian.Uint64(hash[:8]) % uint64(width)))
}

func nextDue(r contract.Resource) time.Time {
	if r.Status.State == "queued" {
		if r.Status.NextAttempt.IsZero() {
			return time.Unix(1, 0)
		}
		return r.Status.NextAttempt
	}
	// An interrupted attempt must be recoverable even when automatic renewal is
	// disabled. Its durable lease time fences duplicate requests after restart.
	if r.Status.State == "issuing" {
		return r.Status.NextAttempt
	}
	if !r.Config.AutoRenew {
		return time.Time{}
	}
	if !r.Status.NextAttempt.IsZero() {
		return r.Status.NextAttempt
	}
	return renewalTime(r.Config.ID, r.Status.Serial, r.Status.NotBefore, r.Status.NotAfter, RenewalWindow{})
}

func failureStatus(r contract.Resource, now time.Time, err error) contract.Status {
	status := r.Status
	status.State = "failed"
	status.LastAttempt = now
	status.Failures = min(max(status.Failures, 0), 999) + 1
	status.FailureCode = "acme_request_failed"
	delay := min(6*time.Hour, time.Minute*time.Duration(1<<min(status.Failures-1, 9)))
	// Stable jitter does not change a persisted retry deadline on restart.
	hash := sha256.Sum256([]byte(r.Config.ID + strconv.Itoa(status.Failures)))
	delay += time.Duration(uint64(hash[0]) * uint64(delay/5) / 255)
	if problem, ok := errors.AsType[*acme.Error](err); ok {
		if problem.StatusCode == http.StatusTooManyRequests {
			status.FailureCode = "ca_rate_limited"
			delay = max(delay, time.Hour)
		}
		if problem.Header != nil {
			value := problem.Header.Get("Retry-After")
			if seconds, e := strconv.ParseInt(value, 10, 64); e == nil && seconds > 0 {
				delay = max(delay, time.Duration(min(seconds, 7*24*3600))*time.Second)
			} else if at, e := http.ParseTime(value); e == nil {
				delay = max(delay, min(7*24*time.Hour, at.Sub(now)))
			}
		}
	}
	if problem, ok := errors.AsType[*dnschallenge.Error](err); ok {
		switch problem.Code {
		case "dns_rate_limited", "dns_provider_unavailable", "dns_zone_mismatch", "dns_propagation_timeout", "dns_api_rejected", "dns_network_error":
			status.FailureCode = problem.Code
		default:
			status.FailureCode = "dns_challenge_failed"
		}
		delay = max(delay, min(7*24*time.Hour, problem.RetryAfter))
	}
	status.NextAttempt = now.Add(delay)
	return status
}
