package relay

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/apernet/quic-go"
)

func TestHysteriaStreamCancellationLogLevel(t *testing.T) {
	previous := log.Default()
	t.Cleanup(func() { log.SetDefault(previous) })
	for _, tc := range []struct {
		name  string
		err   error
		level slog.Level
	}{
		{"local cancellation", &quic.StreamError{StreamID: 200}, slog.LevelDebug},
		{"remote cancellation", &quic.StreamError{StreamID: 180, Remote: true}, slog.LevelDebug},
		{"wrapped cancellation", fmt.Errorf("read: %w", &quic.StreamError{StreamID: 200}), slog.LevelDebug},
		{"net operation cancellation", &net.OpError{Op: "write", Net: "quic", Err: &quic.StreamError{Remote: true}}, slog.LevelDebug},
		{"local failure", &quic.StreamError{ErrorCode: 1}, slog.LevelError},
		{"remote failure", &quic.StreamError{ErrorCode: 1, Remote: true}, slog.LevelError},
		{"wrapped failure", fmt.Errorf("read: %w", &quic.StreamError{ErrorCode: 1}), slog.LevelError},
		{"connection closed", &quic.TransportError{ErrorCode: quic.NoError}, slog.LevelDebug},
		{"other failure", errors.New("read failed"), slog.LevelError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var output bytes.Buffer
			log.SetDefault(slog.NewJSONHandler(&output, &slog.HandlerOptions{Level: slog.LevelDebug}))
			logE("relay rw1 -> rw2", tc.err, "dst", "example.com:443")
			var record struct {
				Level string `json:"level"`
				Err   string `json:"err"`
				Dst   string `json:"dst"`
			}
			if err := json.Unmarshal(output.Bytes(), &record); err != nil {
				t.Fatal(err)
			}
			if record.Level != tc.level.String() {
				t.Fatalf("log level = %s, want %s", record.Level, tc.level)
			}
			if record.Err != tc.err.Error() || record.Dst != "example.com:443" {
				t.Fatalf("lost error or destination: %+v", record)
			}
		})
	}
}
