package masque

import (
	"context"
	"errors"
	"net"
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

func TestPacketConnAfterShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	m := &Masque{ctx: ctx}
	pc, err := m.PacketConn(context.Background(), nil)
	if pc != nil || !errors.Is(err, net.ErrClosed) {
		t.Fatalf("PacketConn after shutdown = (%v, %v), want nil, net.ErrClosed", pc, err)
	}
}
