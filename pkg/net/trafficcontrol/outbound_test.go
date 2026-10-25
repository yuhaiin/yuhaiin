package trafficcontrol

import (
	"context"
	"errors"
	"io"
	"net"
	"syscall"
	"testing"
	"testing/synctest"
	"time"
)

func TestOutboundShapingDirectionAndLocalErrorClassification(t *testing.T) {
	for _, direction := range []Direction{Upload, Download} {
		t.Run(map[Direction]string{Upload: "upload", Download: "download"}[direction], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				m := NewManager()
				profile := Profile{}
				rate := Rate{BytesPerSecond: 1, BurstBytes: 1}
				if direction == Upload {
					profile.Upload = rate
				} else {
					profile.Download = rate
				}
				if err := m.Apply(Config{Enabled: true, Global: profile}); err != nil {
					t.Fatal(err)
				}
				raw, peer := net.Pipe()
				defer peer.Close()
				ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
				defer cancel()
				c := WrapOutboundConn(ctx, raw, func() Policy { return m.Resolve("", "") }, nil)
				defer c.Close()
				var n int
				var err error
				if direction == Download {
					go func() { _, _ = peer.Write([]byte("ab")) }()
					n, err = c.Read(make([]byte, 2))
				} else {
					go func() { _, _ = io.Copy(io.Discard, peer) }()
					n, err = c.Write([]byte("ab"))
				}
				if n != 1 || !errors.Is(err, ErrLocalLimit) || !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("n=%d err=%v", n, err)
				}
				usage := m.Usage()
				if direction == Upload && (usage.AdmittedUploadBytes != 1 || usage.AdmittedDownloadBytes != 0) {
					t.Fatal(usage)
				}
				if direction == Download && (usage.AdmittedDownloadBytes != 1 || usage.AdmittedUploadBytes != 0) {
					t.Fatal(usage)
				}
			})
		})
	}
}

type failedOutboundWriter struct{ net.Conn }

func (failedOutboundWriter) Write([]byte) (int, error) {
	return 0, &net.OpError{Op: "write", Err: syscall.ECONNRESET}
}
func (failedOutboundWriter) Close() error { return nil }
func TestOutboundTransportFailureIsNotLocalPacing(t *testing.T) {
	m := NewManager()
	if err := m.Apply(Config{Enabled: true, Global: Profile{Upload: Rate{BytesPerSecond: 65536, BurstBytes: 65536}}}); err != nil {
		t.Fatal(err)
	}
	c := WrapOutboundConn(t.Context(), failedOutboundWriter{}, func() Policy { return m.Resolve("", "") }, nil)
	defer c.Close()
	if _, err := c.Write([]byte("request")); err == nil || errors.Is(err, ErrLocalLimit) || !errors.Is(err, syscall.ECONNRESET) {
		t.Fatal(err)
	}
}
