package http2

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

type slowPoolDialer struct {
	netapi.Proxy
	addr    string
	started chan struct{}
	release chan struct{}
	calls   atomic.Int32
}

func (d *slowPoolDialer) Conn(ctx context.Context, _ netapi.Address) (net.Conn, error) {
	if d.calls.Add(1) == 2 {
		close(d.started)
		select {
		case <-d.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return (&net.Dialer{}).DialContext(ctx, "tcp", d.addr)
}

func newSlowPool(t *testing.T) (*clientConnectionPool, *slowPoolDialer, *pooledConn) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := newServer(l)
	t.Cleanup(func() { s.Close() })
	d := &slowPoolDialer{addr: l.Addr().String(), started: make(chan struct{}), release: make(chan struct{})}
	p, err := NewClient(Config{}, d)
	if err != nil {
		t.Fatal(err)
	}
	pool := p.(*Client).pool
	pool.concurrency = 1
	t.Cleanup(func() { pool.close() })
	entry, err := pool.get(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	return pool, d, entry
}

func TestPoolSlowDialDoesNotBlockReuse(t *testing.T) {
	p, d, first := newSlowPool(t)
	defer close(d.release)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	slow := make(chan error, 1)
	go func() {
		entry, err := p.get(ctx, false)
		if entry != nil {
			entry.conn.Release()
		}
		slow <- err
	}()
	<-d.started
	first.conn.Release()
	done := make(chan *pooledConn, 1)
	go func() { entry, _ := p.get(context.Background(), false); done <- entry }()
	select {
	case entry := <-done:
		if entry != first {
			t.Fatal("did not reuse available connection")
		}
		entry.conn.Release()
	case <-time.After(500 * time.Millisecond):
		t.Fatal("slow dial blocked reuse")
	}
}

func TestPoolWaiterCancellation(t *testing.T) {
	p, d, _ := newSlowPool(t)
	defer close(d.release)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		entry, _ := p.get(ctx, false)
		if entry != nil {
			entry.conn.Release()
		}
	}()
	<-d.started
	waitCtx, waitCancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer waitCancel()
	done := make(chan error, 1)
	go func() { _, err := p.get(waitCtx, false); done <- err }()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("error=%v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("pool waiter ignored context deadline")
	}
}

func TestPoolCloseCancelsDial(t *testing.T) {
	p, d, _ := newSlowPool(t)
	defer close(d.release)
	dial := make(chan error, 1)
	go func() { _, err := p.get(context.Background(), false); dial <- err }()
	<-d.started
	done := make(chan error, 1)
	go func() { done <- p.close() }()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("pool close blocked on dial")
	}
	select {
	case err := <-dial:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("dial error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("pool close did not cancel dial")
	}
	if _, err := p.get(context.Background(), true); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed pool get=%v", err)
	}
}

type pipePoolDialer struct {
	netapi.Proxy
	conn net.Conn
}

func (d pipePoolDialer) Conn(context.Context, netapi.Address) (net.Conn, error) { return d.conn, nil }

func TestPoolCancelsBlockedPreface(t *testing.T) {
	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()
	proxy, err := NewClient(Config{}, pipePoolDialer{conn: local})
	if err != nil {
		t.Fatal(err)
	}
	p := proxy.(*Client).pool
	defer p.close()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := p.get(ctx, false); done <- err }()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("error=%v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("blocked HTTP/2 preface survived deadline")
	}
}
