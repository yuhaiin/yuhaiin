package ssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	gossh "golang.org/x/crypto/ssh"
)

type testUpstream struct {
	netapi.EmptyDispatch
	addr string
}

func (p *testUpstream) Conn(context.Context, netapi.Address) (net.Conn, error) {
	return net.Dial("tcp", p.addr)
}

func (*testUpstream) PacketConn(context.Context, netapi.Address) (net.PacketConn, error) {
	return nil, errors.New("unused")
}

func (*testUpstream) Ping(context.Context, netapi.Address) (uint64, error) {
	return 0, errors.New("unused")
}

func (*testUpstream) Close() error { return nil }

func startSSHServer(t *testing.T) (string, string, *atomic.Int32) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := gossh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	config := &gossh.ServerConfig{
		PasswordCallback: func(_ gossh.ConnMetadata, password []byte) (*gossh.Permissions, error) {
			if string(password) == "secret" {
				return nil, nil
			}
			return nil, errors.New("invalid password")
		},
	}
	config.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var accepted atomic.Int32
	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				conn, chans, reqs, err := gossh.NewServerConn(raw, config)
				if err != nil {
					_ = raw.Close()
					return
				}
				accepted.Add(1)
				defer conn.Close()
				go gossh.DiscardRequests(reqs)
				for ch := range chans {
					if ch.ChannelType() != "direct-tcpip" {
						_ = ch.Reject(gossh.UnknownChannelType, "TCP only")
						continue
					}
					channel, requests, err := ch.Accept()
					if err != nil {
						continue
					}
					go gossh.DiscardRequests(requests)
					go func() {
						_, _ = io.Copy(channel, channel)
						_ = channel.Close()
					}()
				}
			}()
		}
	}()
	return ln.Addr().String(), gossh.FingerprintSHA256(signer.PublicKey()), &accepted
}

func TestSSHTunnelReusesConnection(t *testing.T) {
	addr, fingerprint, accepted := startSSHServer(t)
	p, err := NewClient(configForTest(fingerprint), &testUpstream{addr: addr})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	dst, err := netapi.ParseAddress("tcp", "example.org:443")
	if err != nil {
		t.Fatal(err)
	}
	for _, message := range []string{"hello", "world"} {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		conn, err := p.Conn(ctx, dst)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Write([]byte(message)); err != nil {
			t.Fatal(err)
		}
		buffer := make([]byte, len(message))
		if _, err := io.ReadFull(conn, buffer); err != nil {
			t.Fatal(err)
		}
		if string(buffer) != message {
			t.Fatalf("got %s", buffer)
		}
		_ = conn.Close()
	}
	if accepted.Load() != 1 {
		t.Fatalf("expected one SSH transport, got %d", accepted.Load())
	}
	if _, err := p.PacketConn(context.Background(), dst); !errors.Is(err, errUDPUnsupported) {
		t.Fatalf("UDP error = %v", err)
	}
}

func TestSSHHostKeyMismatch(t *testing.T) {
	addr, _, _ := startSSHServer(t)
	p, err := NewClient(configForTest("SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), &testUpstream{addr: addr})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	dst, _ := netapi.ParseAddress("tcp", "example.org:80")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if conn, err := p.Conn(ctx, dst); err == nil {
		_ = conn.Close()
		t.Fatal("expected host-key mismatch")
	}
}

func TestSSHRejectsUnsafeConfig(t *testing.T) {
	addr, _, _ := startSSHServer(t)
	for _, cfg := range []contractnode.SSH{
		{User: "test", Password: "secret"},
		{User: "test", HostKey: "invalid"},
		{HostKey: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", Password: "secret"},
	} {
		if p, err := NewClient(cfg, &testUpstream{addr: addr}); err == nil {
			_ = p.Close()
			t.Fatalf("accepted invalid config: %+v", cfg)
		}
	}
}

func configForTest(pin string) contractnode.SSH {
	return contractnode.SSH{User: "test", Password: "secret", HostKey: pin}
}
