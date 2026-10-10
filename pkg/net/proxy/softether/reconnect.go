package softether

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
    "github.com/Asutorufa/yuhaiin/pkg/net/proxy/softether/native"
)

// NewOutbound preserves the original fail-closed behavior unless reconnect
// is enabled. An interrupted connection is never replaced with a direct dial.
func NewOutbound(cfg Config, upstream netapi.Proxy) (netapi.Proxy, error) {
	if !cfg.AutoReconnect {
		return NewClient(cfg, upstream)
	}
	return newReconnectingClient(cfg, upstream)
}

// reconnectingClient holds a complete user-mode network stack per established
// SoftEther session. Connections obtained from older sessions do not migrate.
type reconnectingClient struct {
	netapi.EmptyDispatch
	cfg       Config
	upstream  netapi.Proxy
	ctx       context.Context
	cancel    context.CancelFunc
	mu        sync.RWMutex
	current   *Client
	changed   chan struct{}
	stopped   bool
    failure error
	wg        sync.WaitGroup
	closeOnce sync.Once
}

var _ netapi.Proxy = (*reconnectingClient)(nil)

func newReconnectingClient(cfg Config, upstream netapi.Proxy) (*reconnectingClient, error) {
	ctx, cancel := context.WithCancel(context.Background())
	first, err := newClientContext(ctx, cfg, upstream)
	if err != nil {
		cancel()
		return nil, err
	}
	r := &reconnectingClient{cfg: cfg, upstream: upstream, ctx: ctx, cancel: cancel,
		current: first, changed: make(chan struct{})}
	r.wg.Add(1)
	go func() { defer r.wg.Done(); r.supervise(first) }()
	return r, nil
}

func (r *reconnectingClient) notifyLocked() {
	close(r.changed)
	r.changed = make(chan struct{})
}

func (r *reconnectingClient) supervise(current *Client) {
	backoff := time.Second
	for {
		select {
		case <-r.ctx.Done():
			return
		case <-current.ctx.Done():
		}
		r.mu.Lock()
		if r.stopped {
			r.mu.Unlock()
			return
		}
		if r.current == current {
			r.current = nil
			r.notifyLocked()
		}
		r.mu.Unlock()

		for {
			// Avoid tight loops during outages or rejected credentials.
			timer := time.NewTimer(backoff)
			select {
			case <-r.ctx.Done():
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				return
			case <-timer.C:
			}
			next, err := newClientContext(r.ctx, r.cfg, r.upstream)
			if err == nil {
				r.mu.Lock()
				if r.stopped {
					r.mu.Unlock()
					_ = next.Close()
					return
				}
				r.current = next
				current = next
				r.notifyLocked()
				r.mu.Unlock()
				backoff = time.Second
				break
			}
			if r.ctx.Err() != nil {
				return
			}
			// Do not hammer an authentication server with invalid credentials.
			if errors.Is(err, context.Canceled) {return}
            if errors.Is(err,native.ErrAuth) {
                r.mu.Lock()
                r.failure=err
                r.notifyLocked()
                r.mu.Unlock()
                return
            }
			if backoff < time.Minute {
				backoff *= 2
				if backoff > time.Minute {
					backoff = time.Minute
				}
			}
		}
	}
}

func (r *reconnectingClient) available(ctx context.Context) (*Client, error) {
	for {
		r.mu.RLock()
		c, changed, stopped, failure := r.current, r.changed, r.stopped,r.failure
		if c != nil && c.running.Load() && !stopped {
			r.mu.RUnlock()
			return c, nil
		}
		r.mu.RUnlock()
		if stopped {return nil,net.ErrClosed}
        if failure!=nil{return nil,failure}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-r.ctx.Done():
			return nil, net.ErrClosed
		case <-changed:
		}
	}
}

func (r *reconnectingClient) Conn(ctx context.Context, addr netapi.Address) (net.Conn, error) {
	client, err := r.available(ctx)
	if err != nil {
		return nil, err
	}
	return client.Conn(ctx, addr)
}

func (r *reconnectingClient) PacketConn(ctx context.Context, addr netapi.Address) (net.PacketConn, error) {
	client, err := r.available(ctx)
	if err != nil {
		return nil, err
	}
	return client.PacketConn(ctx, addr)
}

func (r *reconnectingClient) Ping(ctx context.Context, addr netapi.Address) (uint64, error) {
	client, err := r.available(ctx)
	if err != nil {
		return 0, err
	}
	return client.Ping(ctx, addr)
}

func (r *reconnectingClient) Close() error {
	var closeErr error
	r.closeOnce.Do(func() {
		r.mu.Lock()
		r.stopped = true
		r.cancel()
		c := r.current
		r.current = nil
		r.notifyLocked()
		r.mu.Unlock()
		if c != nil {
			closeErr = c.Close()
		}
		r.wg.Wait()
	})
	return closeErr
}
