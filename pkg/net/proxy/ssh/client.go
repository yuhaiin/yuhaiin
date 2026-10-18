// Package ssh provides an SSH direct-tcpip outbound for node protocol chains.
package ssh

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"slices"
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
	upstream  netapi.Proxy
	config    gossh.ClientConfig
	keepAlive time.Duration

	mu           sync.Mutex
	client       *gossh.Client
	done         chan struct{}
	closed       bool
	initializing chan struct{}
	cancel       context.CancelFunc
}

func NewClient(config contractnode.SSH, upstream netapi.Proxy) (netapi.Proxy, error) {
	if upstream == nil || register.IsZero(upstream) {
		return nil, errors.New("SSH requires an upstream transport (normally a simple/fixed SSH server endpoint)")
	}
	if strings.TrimSpace(config.User) == "" {
		return nil, errors.New("SSH username is required")
	}
	callback, algorithms, err := pinnedHostKey(config.HostKey)
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
			HostKeyAlgorithms: algorithms,
		},
		keepAlive: time.Duration(config.KeepAliveSeconds) * time.Second,
	}, nil
}

// Host key verification is mandatory. Accept either the OpenSSH SHA256
// fingerprint or an authorized_keys-style public key (ssh-ed25519 AAAA...).
func pinnedHostKey(pin string) (gossh.HostKeyCallback, []string, error) {
	pin = strings.TrimSpace(pin)
	if pin == "" {
		return nil, nil, errors.New("a pinned public key or SHA256 fingerprint is required")
	}
	if after, ok := strings.CutPrefix(pin, "SHA256:"); ok {
		digest, err := base64.RawStdEncoding.DecodeString(after)
		if err != nil || len(digest) != 32 {
			return nil, nil, errors.New("invalid SHA256 fingerprint")
		}
		return func(_ string, _ net.Addr, key gossh.PublicKey) error {
			if gossh.FingerprintSHA256(key) != pin {
				return fmt.Errorf("SSH host key mismatch: got %s", gossh.FingerprintSHA256(key))
			}
			return nil
		}, nil, nil
	}
	want, _, _, _, err := gossh.ParseAuthorizedKey([]byte(pin))
	if err != nil {
		return nil, nil, fmt.Errorf("expected an OpenSSH public key or SHA256 fingerprint: %w", err)
	}
	algorithms := []string{want.Type()}
	switch want.Type() {
	case gossh.KeyAlgoRSA:
		algorithms = []string{gossh.KeyAlgoRSASHA512, gossh.KeyAlgoRSASHA256}
	case gossh.CertAlgoRSAv01:
		algorithms = []string{gossh.CertAlgoRSASHA512v01, gossh.CertAlgoRSASHA256v01}
	}
	supported := gossh.SupportedAlgorithms().HostKeys
	algorithms = slices.DeleteFunc(algorithms, func(algorithm string) bool { return !slices.Contains(supported, algorithm) })
	if len(algorithms) == 0 {
		return nil, nil, errors.New("pinned host key has no supported secure signature algorithm")
	}
	return func(_ string, _ net.Addr, key gossh.PublicKey) error {
		if !bytes.Equal(want.Marshal(), key.Marshal()) {
			return fmt.Errorf("SSH host key mismatch: got %s", gossh.FingerprintSHA256(key))
		}
		return nil
	}, algorithms, nil
}

// getClient serializes initialization without holding mu during network I/O.
// Each waiter can cancel independently, and Close can cancel the initializer.
func (c *Client) getClient(ctx context.Context, target netapi.Address) (*gossh.Client, error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			return nil, net.ErrClosed
		}
		if c.client != nil {
			client := c.client
			c.mu.Unlock()
			return client, nil
		}
		if pending := c.initializing; pending != nil {
			c.mu.Unlock()
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-pending:
			}
			continue
		}
		handshakeCtx, cancel := context.WithTimeout(ctx, handshakeTimeout)
		pending := make(chan struct{})
		c.initializing, c.cancel = pending, cancel
		c.mu.Unlock()

		client, err := c.establish(handshakeCtx, target)
		cancel()
		c.mu.Lock()
		c.initializing, c.cancel = nil, nil
		if c.closed {
			err = net.ErrClosed
		}
		if err == nil {
			c.client = client
			c.done = make(chan struct{})
			go c.watch(client, c.done)
			if c.keepAlive > 0 {
				go c.keepAliveLoop(client, c.done)
			}
		}
		close(pending)
		c.mu.Unlock()
		if err != nil {
			if client != nil {
				_ = client.Close()
			}
			return nil, err
		}
		return client, nil
	}
}

// establish returns a transport detached from the initial request context.
func (c *Client) establish(ctx context.Context, target netapi.Address) (*gossh.Client, error) {
	raw, err := c.upstream.Conn(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("dial SSH server: %w", err)
	}
	cancelled := make(chan struct{})
	stopCancel := context.AfterFunc(ctx, func() { _ = raw.Close(); close(cancelled) })
	defer stopCancel()
	connection, channels, requests, err := gossh.NewClientConn(raw, raw.RemoteAddr().String(), &c.config)
	// If cancellation has started, wait for its close before returning. A
	// canceled handshake must never publish a transport that is being closed.
	if !stopCancel() {
		<-cancelled
	}
	if ctx.Err() != nil {
		_ = raw.Close()
		return nil, ctx.Err()
	}
	if err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("SSH handshake: %w", err)
	}
	return gossh.NewClient(connection, channels, requests), nil
}

func (c *Client) watch(client *gossh.Client, done chan struct{}) {
	_ = client.Wait()
	c.invalidate(client)
	close(done)
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
			if !c.probe(client, done) {
				c.invalidate(client)
				return
			}
		}
	}
}

// A negative reply still proves liveness; only errors and missing replies
// invalidate the transport. Closing it also releases the pending request.
func (c *Client) probe(client *gossh.Client, done <-chan struct{}) bool {
	result := make(chan error, 1)
	go func() { _, _, err := client.SendRequest("keepalive@openssh.com", true, nil); result <- err }()
	timer := time.NewTimer(c.keepAlive)
	defer timer.Stop()
	select {
	case <-done:
		return true
	case err := <-result:
		return err == nil
	case <-timer.C:
		return false
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
	client, err := c.getClient(ctx, target)
	if err != nil {
		return nil, err
	}
	conn, err := client.DialContext(ctx, "tcp", target.String())
	if err != nil {
		return nil, fmt.Errorf("SSH direct-tcpip %s: %w", target, err)
	}
	return wrapChannel(conn), nil
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
	cancel := c.cancel
	c.client = nil
	c.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if client != nil {
		_ = client.Close()
	}
	return c.upstream.Close()
}
