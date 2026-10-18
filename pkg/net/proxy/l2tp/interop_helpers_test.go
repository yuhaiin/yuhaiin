//go:build l2tp_interop

package l2tp

import (
	"bytes"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestTCPEchoIntegrity(t *testing.T) {
	for _, mode := range []string{"fragmented", "corrupted", "truncated"} {
		t.Run(mode, func(t *testing.T) {
			client, server := net.Pipe()
			finished := make(chan struct{})
			defer func() { _ = client.Close(); <-finished }()
			_ = client.SetDeadline(time.Now().Add(2 * time.Second))
			go func() {
				defer close(finished)
				defer server.Close()
				var buffer [8192]byte
				for {
					n, err := server.Read(buffer[:])
					if err != nil {
						return
					}
					if mode == "corrupted" {
						buffer[0] ^= 1
					}
					if mode == "truncated" {
						_, _ = server.Write(buffer[:n/2])
						return
					}
					for offset := 0; offset < n; {
						end := min(n, offset+127)
						if _, err := server.Write(buffer[offset:end]); err != nil {
							return
						}
						offset = end
					}
				}
			}()
			err := exchangeTCPEcho(client, bytes.Repeat([]byte("echo-integrity"), 8193))
			switch mode {
			case "fragmented":
				if err != nil {
					t.Fatal(err)
				}
			case "corrupted":
				if err == nil || !strings.Contains(err.Error(), "payload mismatch") {
					t.Fatalf("expected corrupted echo rejection, got %v", err)
				}
			case "truncated":
				if !errors.Is(err, io.ErrUnexpectedEOF) {
					t.Fatalf("expected truncated echo rejection, got %v", err)
				}
			}
		})
	}
}
