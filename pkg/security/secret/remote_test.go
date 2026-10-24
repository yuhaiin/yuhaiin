package secret

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
)

func TestRemoteDiagnosticsNeverIncludeSourceProofs(t *testing.T) {
	raw := "https://user:private-password@example.test/capability-private-path?key=private-query"
	for _, err := range []error{&url.Error{Op: "Get", URL: raw, Err: errors.New("private-response-body")}, errors.New("private-response-body")} {
		if strings.Contains(RemoteError(err).Error(), "private") {
			t.Fatal("remote error leaked a proof")
		}
	}
	if strings.Contains(PublicURL(raw), "private") || PublicURL(raw) != "https://example.test/[redacted]" {
		t.Fatal("log URL leaked a proof")
	}
	if !errors.Is(RemoteError(context.Canceled), context.Canceled) || !errors.Is(RemoteError(context.DeadlineExceeded), context.DeadlineExceeded) {
		t.Fatal("cancellation semantics were lost")
	}
}
