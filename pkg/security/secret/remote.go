package secret

import (
	"context"
	"errors"
	"net"
	"net/url"
)

// RemoteError exposes only a bounded failure class. URL errors and arbitrary
// remote response bodies can contain passwords, capability paths or query keys.
// Callers may add a public resource ID and HTTP status, never the request URL.
func RemoteError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	if e, ok := errors.AsType[net.Error](err); ok && e.Timeout() {
		return errors.New("remote request timed out")
	}
	return errors.New("remote request failed")
}

func PublicURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "[redacted URL]"
	}
	return u.Scheme + "://" + u.Host + "/[redacted]"
}
