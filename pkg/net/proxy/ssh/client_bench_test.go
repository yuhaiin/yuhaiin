package ssh

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"io"
	"net"
	"os"
	"os/exec"
	"testing"
)

type benchmarkServerInfo struct {
	SSH string
	Pin string
	TCP string
}

// The server runs in a child process so client and server do not compete
// within one Go scheduler. SSH channels echo bytes; no remote WAN is involved.
func TestSSHBenchmarkServerProcess(t *testing.T) {
	if os.Getenv("YUHAIIN_SSH_BENCH_SERVER") != "1" {
		t.Skip("benchmark subprocess")
	}
	addr, pin, _ := startSSHServer(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
		}
	}()
	if err := json.MarshalWrite(os.Stdout, benchmarkServerInfo{SSH: addr, Pin: pin, TCP: ln.Addr().String()}); err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, os.Stdin)
}

func startBenchmarkServer(b *testing.B) benchmarkServerInfo {
	b.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestSSHBenchmarkServerProcess$", "-test.timeout=2m")
	cmd.Env = append(os.Environ(), "YUHAIIN_SSH_BENCH_SERVER=1")
	cmd.Stderr = os.Stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		b.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		b.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() {
		_ = stdin.Close()
		if err := cmd.Wait(); err != nil {
			b.Error(err)
		}
	})
	// MarshalWrite emits one JSON value; avoid waiting for EOF on the pipe.
	var info benchmarkServerInfo
	decoder := jsontext.NewDecoder(stdout)
	if err := json.UnmarshalDecode(decoder, &info); err != nil {
		b.Fatal(err)
	}
	return info
}

func BenchmarkSSH(b *testing.B) {
	info := startBenchmarkServer(b)
	dst := testTarget(b)
	b.Run("ColdHandshake", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			p, err := NewClient(configForTest(info.Pin), &testUpstream{addr: info.SSH})
			if err != nil {
				b.Fatal(err)
			}
			conn, err := p.Conn(b.Context(), dst)
			if err != nil {
				_ = p.Close()
				b.Fatal(err)
			}
			_ = conn.Close()
			_ = p.Close()
		}
	})
	b.Run("ReusedTransportChannel", func(b *testing.B) {
		p := newTestClient(b, info.SSH, info.Pin)
		conn, err := p.Conn(b.Context(), dst)
		if err != nil {
			b.Fatal(err)
		}
		_ = conn.Close()
		b.ReportAllocs()
		for b.Loop() {
			conn, err := p.Conn(b.Context(), dst)
			if err != nil {
				b.Fatal(err)
			}
			_ = conn.Close()
		}
	})
	for _, protocol := range []string{"TCP", "SSH"} {
		for _, size := range []struct {
			name  string
			bytes int
		}{{"1KiB", 1024}, {"32KiB", 32 * 1024}, {"1MiB", 1024 * 1024}} {
			b.Run(protocol+"/Echo/"+size.name, func(b *testing.B) {
				var conn net.Conn
				var err error
				if protocol == "SSH" {
					p := newTestClient(b, info.SSH, info.Pin)
					conn, err = p.Conn(b.Context(), dst)
				} else {
					conn, err = net.Dial("tcp", info.TCP)
				}
				if err != nil {
					b.Fatal(err)
				}
				defer conn.Close()
				payload, received := make([]byte, size.bytes), make([]byte, size.bytes)
				b.SetBytes(int64(size.bytes))
				b.ReportAllocs()
				for b.Loop() {
					if _, err := conn.Write(payload); err != nil {
						b.Fatal(err)
					}
					if _, err := io.ReadFull(conn, received); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
	b.Run("ParallelChannels", func(b *testing.B) {
		p := newTestClient(b, info.SSH, info.Pin)
		conn, err := p.Conn(b.Context(), dst)
		if err != nil {
			b.Fatal(err)
		}
		_ = conn.Close()
		b.ReportAllocs()
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				conn, err := p.Conn(b.Context(), dst)
				if err != nil {
					b.Error(err)
					return
				}
				_ = conn.Close()
			}
		})
	})
}
