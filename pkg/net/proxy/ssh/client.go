// Package ssh provides an SSH direct-tcpip outbound for node protocol chains.
package ssh

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/register"
	gossh "golang.org/x/crypto/ssh"
)

const handshakeTimeout = 15 * time.Second

var errUDPUnsupported = errors.New("SSH direct-tcpip outbound does not support UDP; configure a different UDP node")

func init() {
	register.RegisterContractPoint("ssh", func(config contractnode.SSH, p netapi.Proxy) (netapi.Proxy, error) {
		return NewClient(config, p)
	})
}

// Client reuses one SSH transport for any number of direct-tcpip channels.
type Client struct {
	netapi.EmptyDispatch
	upstream netapi.Proxy
	config   gossh.ClientConfig
	keepAlive time.Duration

	mu     sync.Mutex
	client *gossh.Client
	done   chan struct{}
	closed bool
}

func NewClient(config contractnode.SSH, upstream netapi.Proxy) (netapi.Proxy, error) {
	if upstream == nil || register.IsZero(upstream) {
		return nil, errors.New("SSH requires an upstream transport (normally a simple/fixed SSH server endpoint)")
	}
	if strings.TrimSpace(config.User) == "" {
		return nil, errors.New("SSH username is required")
	}
	callback, err := pinnedHostKey(config.HostKey)
	if err != nil {
		return nil, fmt.Errorf("SSH server host key: %w", err)
	}
	if config.KeepAliveSeconds < 0 || config.KeepAliveSeconds > 3600 {
		return nil, errors.New("SSH keep-alive seconds must be between 0 and 3600")
	}
	var methods []gossh.AuthMethod
	if config.PrivateKey != "" {
		var signer gossh.Signer
		if config.PrivateKeyPassphrase != "" {
			signer, err = gossh.ParsePrivateKeyWithPassphrase([]byte(config.PrivateKey), []byte(config.PrivateKeyPassphrase))
		} else {
			signer, err = gossh.ParsePrivateKey([]byte(config.PrivateKey))
		}
		if err != nil {
			return nil, fmt.Errorf("parse SSH private key: %w", err)
		}
		methods = append(methods, gossh.PublicKeys(signer))
	}
	if config.Password != "" {
		methods = append(methods, gossh.Password(config.Password))
	}
	if len(methods) == 0 {
		return nil, errors.New("SSH password or private key is required")
	}
	return &Client{
		upstream: upstream,
		config: gossh.ClientConfig{
			User: strings.TrimSpace(config.User), Auth: methods, HostKeyCallback: callback,
		},
		keepAlive: time.Duration(config.KeepAliveSeconds) * time.Second,
	}, nil
}

// Host key verification is mandatory. Accept either the OpenSSH SHA256
// fingerprint or an authorized_keys-style public key (ssh-ed25519 AAAA...).
func pinnedHostKey(pin string) (gossh.HostKeyCallback, error) {
	pin = strings.TrimSpace(pin)
	if pin == "" {
		return nil, errors.New("a pinned public key or SHA256 fingerprint is required")
	}
	if strings.HasPrefix(pin, "SHA256:") {
		digest, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(pin, "SHA256:"))
		if err != nil || len(digest) != 32 {
			return nil, errors.New("invalid SHA256 fingerprint")
		}
		return func(_ string, _ net.Addr, key gossh.PublicKey) error {
			if gossh.FingerprintSHA256(key) != pin {
				return fmt.Errorf("SSH host key mismatch: got %s", gossh.FingerprintSHA256(key))
			}
			return nil
		}, nil
	}
	want, _, _, _, err := gossh.ParseAuthorizedKey([]byte(pin))
	if err != nil {
		return nil, fmt.Errorf("expected an OpenSSH public key or SHA256 fingerprint: %w", err)
	}
	return func(_ string, _ net.Addr, key gossh.PublicKey) error {
		if !bytes.Equal(want.Marshal(), key.Marshal()) {
			return fmt.Errorf("SSH host key mismatch: got %s", gossh.FingerprintSHA256(key))
		}
		return nil
	}, nil
}

// establish must run with mu held. Dial and handshake are bounded and cancelled,
// while successful channels are independent of the original request context.
func (c *Client) establish(ctx context.Context, target netapi.Address) (*gossh.Client, error) {
	if c.closed {
		return nil, net.ErrClosed
	}
	if c.client != nil {
		return c.client, nil
	}
	handshakeCtx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	raw, err := c.upstream.Conn(handshakeCtx, target)
	if err != nil {
		return nil, fmt.Errorf("dial SSH server: %w", err)
	}
	deadline, _ := handshakeCtx.Deadline()
	if err := raw.SetDeadline(deadline); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("set SSH handshake deadline: %w", err)
	}
	stopCancel := context.AfterFunc(handshakeCtx, func() { _ = raw.Close() })
	defer stopCancel()
	connection, channels, requests, err := gossh.NewClientConn(raw, raw.RemoteAddr().String(), &c.config)
	if err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("SSH handshake: %w", err)
	}
	if err := handshakeCtx.Err(); err != nil {
		_ = raw.Close()
		return nil, err
	}
	// Stop the handshake deadline and cancellation hook before publishing the
	// multiplexed connection, which must survive individual request contexts.
	stopCancel()
	if err := raw.SetDeadline(time.Time{}); err != nil {
		_ = raw.Close()
		return nil, err
	}
	client := gossh.NewClient(connection, channels, requests)
	c.client = client
	c.done = make(chan struct{})
	go c.watch(client, c.done)
	if c.keepAlive > 0 {
		go c.keepAliveLoop(client, c.done)
	}
	return client, nil
}

func (c *Client) watch(client *gossh.Client, done chan struct{}) {
	_ = client.Wait()
	close(done)
	c.invalidate(client)
}

func (c *Client) invalidate(client *gossh.Client) {
	c.mu.Lock()
	if c.client == client {
		c.client = nil
	}
	c.mu.Unlock()
	_ = client.Close()
}

func (c *Client) keepAliveLoop(client *gossh.Client, done <-chan struct{}) {
	ticker := time.NewTicker(c.keepAlive)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			_, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
			if err != nil {
				c.invalidate(client)
				return
			}
		}
	}
}

func (c *Client) Conn(ctx context.Context, target netapi.Address) (net.Conn, error) {
	switch target.Network() {
	case "", "tcp", "tcp4", "tcp6":
	default:
		return nil, fmt.Errorf("SSH only supports TCP, got %q", target.Network())
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.mu.Lock()
	client, err := c.establish(ctx, target)
	c.mu.Unlock()
	if err != nil {
		return nil, err
	}
	conn, err := client.DialContext(ctx, "tcp", target.String())
	if err != nil {
		return nil, fmt.Errorf("SSH direct-tcpip %s: %w", target, err)
	}
	return conn, nil
}

func (*Client) PacketConn(context.Context, netapi.Address) (net.PacketConn, error) {
	return nil, errUDPUnsupported
}

func (c *Client) Ping(ctx context.Context, target netapi.Address) (uint64, error) {
	start := time.Now()
	conn, err := c.Conn(ctx, target)
	if err != nil {
		return 0, err
	}
	_ = conn.Close()
	return uint64(time.Since(start)), nil
}

func (c *Client) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	client := c.client
	c.client = nil
	c.mu.Unlock()
	if client != nil {
		_ = client.Close()
	}
	return c.upstream.Close()
}
