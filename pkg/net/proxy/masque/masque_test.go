package masque

import (
	"context"
	"errors"
	"testing"
)

func TestIsRetryableHTTP3ConnectFailure(t *testing.T) {
	cases := []struct {
		err   error
		retry bool
	}{
		{nil, false},
		{errors.New("connect-ip: failed to read response: http3: parsing frame failed: PROTOCOL_VIOLATION (remote)"), true},
		{errors.New("tls: access denied"), false},
		{errors.New("PROTOCOL_VIOLATION from unrelated phase"), false},
		{context.Canceled, false},
	}
	for _, tc := range cases {
		if got := isRetryableHTTP3ConnectFailure(tc.err); got != tc.retry {
			t.Errorf("isRetryableHTTP3ConnectFailure(%v) = %v, want %v", tc.err, got, tc.retry)
		}
	}
}
