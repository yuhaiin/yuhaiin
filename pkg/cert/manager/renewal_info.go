package manager

import (
	"context"
	"crypto/tls"
	"errors"
	"time"
	"uuid"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/certificate"
	"github.com/Asutorufa/yuhaiin/pkg/store/certificates"
)

func renewalInfoDue(r contract.Resource, now time.Time) time.Time {
	if !r.Config.AutoRenew || r.Status.State != "ready" || r.Status.Failures > 0 || r.Status.Serial == "" || !now.Before(r.Status.NotAfter) {
		return time.Time{}
	}
	if r.Status.RenewalInfo == nil || r.Status.RenewalInfo.NextCheck.IsZero() {
		return time.Unix(1, 0)
	}
	return r.Status.RenewalInfo.NextCheck
}

func (m *Manager) applyRenewalInfo(ctx context.Context, config contract.Config, pair *tls.Certificate, status contract.Status) contract.Status {
	now := m.options.Now()
	result, err := m.options.RenewalInfo(ctx, config, pair)
	info := contract.RenewalInfoStatus{CheckedAt: now, NextCheck: now.Add(6 * time.Hour), State: "unavailable"}
	if status.RenewalInfo != nil {
		info.Failures = status.RenewalInfo.Failures
	}
	if err != nil {
		info.Failures = min(max(info.Failures, 0), 999) + 1
		if e, ok := errors.AsType[*renewalInfoError](err); ok {
			if e.temporary && info.Failures <= 5 {
				info.NextCheck = now.Add(time.Minute * time.Duration(1<<min(info.Failures-1, 4)))
			}
			info.NextCheck = maxTime(info.NextCheck, now.Add(e.retryAfter))
		}
		if !errors.Is(ctx.Err(), context.Canceled) {
			m.report("certificate_renewal_info_unavailable")
		}
	} else {
		info.State, info.Failures = "unsupported", 0
		if result.NextCheck.IsZero() {
			result.NextCheck = now.Add(6 * time.Hour)
		}
		info.NextCheck = minTime(maxTime(result.NextCheck, now.Add(time.Minute)), now.Add(24*time.Hour))
		if result.Supported {
			window := result.Window
			if window.Start.IsZero() || !window.End.After(window.Start) || !window.Start.Before(pair.Leaf.NotAfter) {
				info.State, info.NextCheck = "unavailable", now.Add(6*time.Hour)
			} else {
				info.State, info.WindowStart, info.WindowEnd, info.ExplanationURL = "available", window.Start, minTime(window.End, pair.Leaf.NotAfter), renewalExplanationURL(result.ExplanationURL)
				chosen := renewalTime(config.ID, status.Serial, status.NotBefore, status.NotAfter, RenewalWindow{info.WindowStart, info.WindowEnd})
				status.NextAttempt = maxTime(chosen, status.LastAttempt.Add(certificates.ManualAttemptInterval))
			}
		}
	}
	status.RenewalInfo = &info
	return status
}

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

func (m *Manager) refreshRenewalInfo(ctx context.Context, resource contract.Resource) (bool, error) {
	now := m.options.Now()
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return false, nil
	}
	owner := uuid.New().String()
	acquired, err := m.options.Store.AcquireRenewalInfo(ctx, resource.Config.ID, resource.Revision, resource.Status.Serial, owner, now)
	if err != nil || !acquired {
		m.mu.Unlock()
		return false, err
	}
	bounded, cancel := context.WithTimeout(ctx, time.Minute)
	m.activeID, m.activeCancel = resource.Config.ID, cancel
	m.mu.Unlock()
	defer func() { cancel(); m.mu.Lock(); m.activeID = ""; m.activeCancel = nil; m.mu.Unlock() }()
	// The serial check prevents refreshing replaced material even after a cache
	// reload or competing manager. No old leaf is queried after replacement.
	pair := m.Cache.snapshot.Load().pairs[resource.Config.ID]
	status := resource.Status
	if pair == nil || pair.Leaf.SerialNumber.String() != status.Serial || !now.Before(pair.Leaf.NotAfter) {
		status.RenewalInfo = &contract.RenewalInfoStatus{State: "unavailable", CheckedAt: now, NextCheck: now.Add(6 * time.Hour)}
	} else {
		status = m.applyRenewalInfo(bounded, resource.Config, pair, status)
	}
	if ctx.Err() != nil {
		return true, nil
	}
	if err := m.options.Store.Complete(ctx, resource.Config.ID, resource.Revision, owner, m.options.Now(), status, nil); err != nil {
		if errors.Is(err, certificates.ErrConflict) {
			return true, nil
		}
		return true, err
	}
	if status.RenewalInfo != nil && status.RenewalInfo.State == "available" {
		m.report("certificate_renewal_info_updated")
	}
	return true, nil
}
