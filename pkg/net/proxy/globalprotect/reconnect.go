package globalprotect

import (
	"context"
	"errors"
	"math/rand/v2"
	"net"
	"sync"
	"time"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

const (
	initialReconnectDelay = time.Second
	maximumReconnectDelay = time.Minute
)

// NewClient connects to a directly addressed GlobalProtect gateway with
// username/password auth. Portal discovery and interactive authentication are
// not attempted. After a successful connection, dropped tunnels are retried
// with capped exponential backoff until the proxy is closed.
func NewClient(config Config, upstream netapi.Proxy) (netapi.Proxy, error) {
	config.upstream = upstream
	if config.InsecureSkipVerify {
		log.Warn("globalprotect TLS certificate verification is disabled")
	}
	client, err := connectClient(context.Background(), config)
	if err != nil {
		return nil, err
	}
	proxy := newReconnectingClient(config, client, connectClient)
	go proxy.run()
	return proxy, nil
}

var _ netapi.Proxy = (*reconnectingClient)(nil)

type reconnectingClient struct {
	netapi.EmptyDispatch
	config       Config
	ctx          context.Context
	cancel       context.CancelFunc
	connect      func(context.Context, Config) (*Client, error)
	initialDelay time.Duration

	mu               sync.Mutex
	client           *Client
	changed          chan struct{}
	demand           chan struct{}
	waitingForDemand bool
	failure          error
	closed           bool
}

func newReconnectingClient(
	config Config,
	client *Client,
	connect func(context.Context, Config) (*Client, error),
) *reconnectingClient {
	ctx, cancel := context.WithCancel(context.Background())
	return &reconnectingClient{
		config: config, ctx: ctx, cancel: cancel,
		connect: connect, initialDelay: initialReconnectDelay,
		client: client, changed: make(chan struct{}), demand: make(chan struct{}, 1),
	}
}

func (c *reconnectingClient) run() {
	c.mu.Lock()
	client := c.client
	c.mu.Unlock()
	delay := c.initialDelay

	for client != nil {
		select {
		case <-c.ctx.Done():
			return
		case <-client.done:
		}
		if c.ctx.Err() != nil {
			return
		}

		failure := client.stateError()
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			return
		}
		if c.client == client {
			c.client = nil
			c.waitingForDemand = errors.Is(failure, errGatewayIdleDisconnect)
			c.signalLocked()
		}
		c.mu.Unlock()
		waitForDemand := errors.Is(failure, errGatewayIdleDisconnect)
		if waitForDemand {
			log.Info("globalprotect tunnel disconnected while idle; reconnecting on next request")
		} else {
			log.Warn("globalprotect tunnel disconnected; reconnecting", "error", failure)
		}
		for {
			if waitForDemand {
				select {
				case <-c.ctx.Done():
					return
				case <-c.demand:
				}
				c.mu.Lock()
				c.waitingForDemand = false
				c.mu.Unlock()
				waitForDemand = false
			} else {
				wait := jitterReconnectDelay(delay)
				log.Debug("globalprotect reconnect scheduled", "retry_in", wait)
				timer := time.NewTimer(wait)
				select {
				case <-c.ctx.Done():
					timer.Stop()
					return
				case <-timer.C:
				}
			}

			next, err := c.connect(c.ctx, c.config)
			if err != nil {
				if c.ctx.Err() != nil {
					return
				}
				if errors.Is(err, errAuthenticationRejected) || errors.Is(err, ErrInteractiveAuth) {
					c.mu.Lock()
					if !c.closed {
						c.failure = err
						c.signalLocked()
					}
					c.mu.Unlock()
					log.Error("globalprotect reconnect stopped; manual reconnect is required", "error", err)
					return
				}
				log.Warn("globalprotect reconnect failed", "error", err)
				delay = nextReconnectDelay(delay)
				continue
			}

			c.mu.Lock()
			if c.closed {
				c.mu.Unlock()
				_ = next.Close()
				return
			}
			c.client = next
			c.signalLocked()
			c.mu.Unlock()
			client = next
			delay = c.initialDelay
			log.Info("globalprotect tunnel reconnected")
			break
		}
	}
}

func nextReconnectDelay(delay time.Duration) time.Duration {
	if delay <= 0 {
		return initialReconnectDelay
	}
	if delay >= maximumReconnectDelay/2 {
		return maximumReconnectDelay
	}
	return delay * 2
}

func jitterReconnectDelay(delay time.Duration) time.Duration {
	if delay <= 0 {
		return 0
	}
	spread := delay / 5
	return delay - spread + time.Duration(rand.Int64N(int64(spread)+1))
}

func (c *reconnectingClient) signalLocked() {
	close(c.changed)
	c.changed = make(chan struct{})
}

func (c *reconnectingClient) current(ctx context.Context) (*Client, error) {
	for {
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			return nil, net.ErrClosed
		}
		if c.failure != nil {
			err := c.failure
			c.mu.Unlock()
			return nil, err
		}
		client := c.client
		if client != nil && client.stateError() == nil {
			c.mu.Unlock()
			return client, nil
		}
		if c.waitingForDemand {
			select {
			case c.demand <- struct{}{}:
			default:
			}
		}
		changed := c.changed
		c.mu.Unlock()

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-c.ctx.Done():
			return nil, net.ErrClosed
		case <-changed:
		}
	}
}

func (c *reconnectingClient) Conn(ctx context.Context, address netapi.Address) (net.Conn, error) {
	client, err := c.current(ctx)
	if err != nil {
		return nil, err
	}
	return client.Conn(ctx, address)
}

func (c *reconnectingClient) PacketConn(ctx context.Context, address netapi.Address) (net.PacketConn, error) {
	client, err := c.current(ctx)
	if err != nil {
		return nil, err
	}
	return client.PacketConn(ctx, address)
}

func (c *reconnectingClient) Ping(context.Context, netapi.Address) (uint64, error) {
	return 0, errors.ErrUnsupported
}

func (c *reconnectingClient) NodeExtraInfo() contractnode.NodeExtraInfo {
	c.mu.Lock()
	client := c.client
	c.mu.Unlock()
	if client == nil || client.stateError() != nil {
		return contractnode.NodeExtraInfo{}
	}
	return client.NodeExtraInfo()
}

func (c *reconnectingClient) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	client := c.client
	c.client = nil
	c.signalLocked()
	c.mu.Unlock()
	c.cancel()
	if client == nil {
		return nil
	}
	return client.Close()
}
