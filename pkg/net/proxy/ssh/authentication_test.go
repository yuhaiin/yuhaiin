package ssh

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"slices"
	"testing"
	"time"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	gossh "golang.org/x/crypto/ssh"
)

type testForwardRequest struct {
	Host       string
	Port       uint32
	Origin     string
	OriginPort uint32
}

func startForwardingSSHServer(t *testing.T, hostKeys []gossh.Signer, allowed gossh.PublicKey, destination ...string) (string, <-chan testForwardRequest) {
	t.Helper()
	config := &gossh.ServerConfig{
		PasswordCallback: func(_ gossh.ConnMetadata, pass []byte) (*gossh.Permissions, error) {
			if string(pass) == "secret" {
				return nil, nil
			}
			return nil, errors.New("bad password")
		},
		PublicKeyCallback: func(_ gossh.ConnMetadata, key gossh.PublicKey) (*gossh.Permissions, error) {
			if bytes.Equal(key.Marshal(), allowed.Marshal()) {
				return nil, nil
			}
			return nil, errors.New("bad public key")
		},
	}
	for _, key := range hostKeys {
		config.AddHostKey(key)
	}
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = echo.Close() })
	targetAddress := echo.Addr().String()
	if len(destination) != 0 {
		targetAddress = destination[0]
	}
	go func() {
		for {
			conn, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
		}
	}()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	forwarded := make(chan testForwardRequest, 32)
	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				conn, channels, requests, err := gossh.NewServerConn(raw, config)
				if err != nil {
					_ = raw.Close()
					return
				}
				defer conn.Close()
				go gossh.DiscardRequests(requests)
				for incoming := range channels {
					var request testForwardRequest
					if incoming.ChannelType() != "direct-tcpip" || gossh.Unmarshal(incoming.ExtraData(), &request) != nil {
						_ = incoming.Reject(gossh.UnknownChannelType, "unsupported")
						continue
					}
					forwarded <- request
					// Resolve the remote-only test name on the server and forward
					// to a separate real TCP echo socket, rather than SSH echo.
					target, err := net.Dial("tcp", targetAddress)
					if err != nil {
						_ = incoming.Reject(gossh.ConnectionFailed, err.Error())
						continue
					}
					channel, reqs, err := incoming.Accept()
					if err != nil {
						_ = target.Close()
						continue
					}
					go gossh.DiscardRequests(reqs)
					go func() { defer target.Close(); defer channel.Close(); _, _ = io.Copy(target, channel) }()
					go func() { defer target.Close(); defer channel.Close(); _, _ = io.Copy(channel, target) }()
				}
			}()
		}
	}()
	return ln.Addr().String(), forwarded
}

func newTestSigner(t *testing.T) (ed25519.PrivateKey, gossh.Signer) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := gossh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return key, signer
}

func TestSSHAuthenticationAndForwarding(t *testing.T) {
	_, host := newTestSigner(t)
	private, auth := newTestSigner(t)
	plain, err := gossh.MarshalPrivateKey(private, "test")
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := gossh.MarshalPrivateKeyWithPassphrase(private, "test", []byte("passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	addr, forwarded := startForwardingSSHServer(t, []gossh.Signer{host}, auth.PublicKey())
	for _, tc := range []struct {
		name   string
		config contractnode.SSH
	}{
		{"password", configForTest(gossh.FingerprintSHA256(host.PublicKey()))},
		{"private-key-public-pin", contractnode.SSH{User: "test", PrivateKey: string(pem.EncodeToMemory(plain)), HostKey: string(gossh.MarshalAuthorizedKey(host.PublicKey()))}},
		{"encrypted-private-key", contractnode.SSH{User: "test", PrivateKey: string(pem.EncodeToMemory(encrypted)), PrivateKeyPassphrase: "passphrase", HostKey: gossh.FingerprintSHA256(host.PublicKey())}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			proxy, err := NewClient(tc.config, &testUpstream{addr: addr})
			if err != nil {
				t.Fatal(err)
			}
			defer proxy.Close()
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			conn, err := proxy.Conn(ctx, testTarget(t))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			request := <-forwarded
			if request.Host != "remote-only.invalid" || request.Port != 443 {
				t.Fatalf("forwarded destination = %+v", request)
			}
			message := []byte("real TCP target via SSH")
			if _, err := conn.Write(message); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, len(message))
			if _, err := io.ReadFull(conn, got); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, message) {
				t.Fatalf("got %q", got)
			}
		})
	}
	t.Run("wrong-key-passphrase", func(t *testing.T) {
		cfg := configForTest(gossh.FingerprintSHA256(host.PublicKey()))
		cfg.PrivateKey = string(pem.EncodeToMemory(encrypted))
		cfg.PrivateKeyPassphrase = "wrong"
		if p, err := NewClient(cfg, &testUpstream{addr: addr}); err == nil {
			_ = p.Close()
			t.Fatal("accepted wrong passphrase")
		}
	})
}

func TestSSHPinnedHostKeyAlgorithm(t *testing.T) {
	_, host := newTestSigner(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	other, err := gossh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	_, auth := newTestSigner(t)
	addr, _ := startForwardingSSHServer(t, []gossh.Signer{host, other}, auth.PublicKey())
	// A typical SSH server advertises several host keys. A full Ed25519
	// public-key pin provides enough information to select that algorithm.
	p := newTestClient(t, addr, string(gossh.MarshalAuthorizedKey(host.PublicKey())))
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	conn, err := p.Conn(ctx, testTarget(t))
	if err != nil {
		t.Fatalf("server advertises the pinned Ed25519 key, but client negotiates another key: %v", err)
	}
	_ = conn.Close()
}

func TestSSHPinnedRSAUsesSHA2(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	host, err := gossh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	_, auth := newTestSigner(t)
	addr, _ := startForwardingSSHServer(t, []gossh.Signer{host}, auth.PublicKey())
	p := newTestClient(t, addr, string(gossh.MarshalAuthorizedKey(host.PublicKey())))
	if !slices.Equal(p.config.HostKeyAlgorithms, []string{gossh.KeyAlgoRSASHA512, gossh.KeyAlgoRSASHA256}) {
		t.Fatalf("RSA host key algorithms = %v", p.config.HostKeyAlgorithms)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	conn, err := p.Conn(ctx, testTarget(t))
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
}
