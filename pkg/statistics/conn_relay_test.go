package statistics

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/pipe"
	"github.com/Asutorufa/yuhaiin/pkg/net/relay"
	"github.com/Asutorufa/yuhaiin/pkg/pool"
)

type relayConnProxy struct {
	netapi.Proxy
	conn net.Conn
}

func (p relayConnProxy) Conn(context.Context, netapi.Address) (net.Conn, error) { return p.conn, nil }

// Use the production Connections.Conn wrapper, including traffic accounting
// and removal, rather than a lookalike wrapper around the pipe.
func countedTestConn(t testing.TB, raw net.Conn) (*Connections, net.Conn) {
	t.Helper()
	c := NewSQLiteConnStore(filepath.Join(t.TempDir(), "connections.db"), nil)
	c.Proxy = relayConnProxy{conn: raw}
	t.Cleanup(func() { _ = c.Close() })
	conn, err := c.Conn(netapi.WithContext(t.Context()), netapi.EmptyAddr)
	if err != nil {
		t.Fatal(err)
	}
	return c, conn
}

type observedPipe struct {
	*pipe.Conn
	entered chan struct{}
	once    sync.Once
}

func (p *observedPipe) Read(b []byte) (int, error) {
	p.once.Do(func() { close(p.entered) })
	return p.Conn.Read(b)
}
func (p *observedPipe) ReadWithBuffer(get func() []byte) ([]byte, error) {
	p.once.Do(func() { close(p.entered) })
	return p.Conn.ReadWithBuffer(get)
}

type observedBufferPool struct {
	pool.Pool
	borrowed chan struct{}
}

func (p observedBufferPool) GetBytes(size int) []byte {
	select {
	case p.borrowed <- struct{}{}:
	default:
	}
	return p.Pool.GetBytes(size)
}

func TestCountedRelayWaitsBeforeBorrowingBuffer(t *testing.T) {
	sender, receiver := pipe.Pipe()
	defer sender.Close()
	c, conn := countedTestConn(t, &observedPipe{Conn: receiver, entered: make(chan struct{})})
	defer conn.Close()
	observed := c.Proxy.(relayConnProxy).conn.(*observedPipe)
	previous := pool.DefaultPool
	borrowed := make(chan struct{}, 16)
	pool.DefaultPool = observedBufferPool{Pool: previous, borrowed: borrowed}
	defer func() { pool.DefaultPool = previous }()
	done := make(chan error, 1)
	stopped := make(chan struct{})
	var received bytes.Buffer
	go func() {
		defer close(stopped)
		_, err := relay.Copy(&received, conn)
		done <- err
	}()
	defer func() {
		_ = conn.Close()
		_ = sender.Close()
		<-stopped // Stop the worker before restoring the global buffer pool.
	}()
	select {
	case <-observed.entered:
	case <-time.After(time.Second):
		t.Fatal("relay did not start reading")
	}
	select {
	case <-borrowed:
		t.Error("idle counted relay borrowed a buffer")
	default:
	}
	payload := bytes.Repeat([]byte("counted traffic"), 8192)
	if _, err := sender.Write(payload); err != nil {
		t.Fatal(err)
	}
	_ = sender.CloseWrite()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("relay did not stop on EOF")
	}
	if !bytes.Equal(received.Bytes(), payload) {
		t.Fatal("corrupted counted relay payload")
	}
	if got := c.Cache.LoadRunningDownload(); got != uint64(len(payload)) {
		t.Fatalf("download=%d, want %d", got, len(payload))
	}
	_ = conn.Close()
	if len(c.allInfos()) != 0 {
		t.Fatal("closed connection remains registered")
	}
}

func TestCountedRelayDeadline(t *testing.T) {
	sender, receiver := pipe.Pipe()
	defer sender.Close()
	c, conn := countedTestConn(t, receiver)
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
	if _, err := relay.Copy(io.Discard, conn); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("deadline did not interrupt relay")
	}
	if c.Cache.LoadRunningDownload() != 0 {
		t.Fatal("deadline counted nonexistent traffic")
	}
}

func BenchmarkCountedPipeRelay(b *testing.B) {
	quietRelayBenchmarkLogs(b)
	for _, size := range []int{64, 16384, 65536} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			writer, reader := pipe.Pipe()
			defer writer.Close()
			c, conn := countedTestConn(b, reader)
			defer conn.Close()
			done := make(chan error, 1)
			go func() { _, err := relay.Copy(io.Discard, conn); done <- err }()
			payload := make([]byte, size)
			b.ReportAllocs()
			b.SetBytes(int64(size))
			for b.Loop() {
				if _, err := writer.Write(payload); err != nil {
					b.Fatal(err)
				}
			}
			_ = writer.CloseWrite()
			if err := <-done; err != nil {
				b.Fatal(err)
			}
			if got := c.Cache.LoadRunningDownload(); got != uint64(b.N)*uint64(size) {
				b.Fatalf("download=%d", got)
			}
		})
	}
}

func BenchmarkCountedIdleRelays(b *testing.B) {
	quietRelayBenchmarkLogs(b)
	const count = 128
	c := NewSQLiteConnStore(filepath.Join(b.TempDir(), "idle.db"), nil)
	defer c.Close()
	var retained uint64
	for b.Loop() {
		b.StopTimer()
		runtime.GC()
		runtime.GC()
		var before runtime.MemStats
		runtime.ReadMemStats(&before)
		b.StartTimer()
		senders := make([]net.Conn, 0, count)
		conns := make([]net.Conn, 0, count)
		done := make(chan error, count)
		for range count {
			sender, receiver := pipe.Pipe()
			raw := &observedPipe{Conn: receiver, entered: make(chan struct{})}
			c.Proxy = relayConnProxy{conn: raw}
			conn, err := c.Conn(netapi.WithContext(b.Context()), netapi.EmptyAddr)
			if err != nil {
				b.Fatal(err)
			}
			senders = append(senders, sender)
			conns = append(conns, conn)
			go func() { _, err := relay.Copy(io.Discard, conn); done <- err }()
			<-raw.entered
		}
		b.StopTimer()
		runtime.GC()
		runtime.GC()
		var after runtime.MemStats
		runtime.ReadMemStats(&after)
		if after.HeapAlloc > before.HeapAlloc {
			retained += after.HeapAlloc - before.HeapAlloc
		}
		for _, conn := range conns {
			_ = conn.Close()
		}
		for _, sender := range senders {
			_ = sender.Close()
		}
		for range count {
			if err := <-done; err != nil && !errors.Is(err, io.ErrClosedPipe) {
				b.Fatal(err)
			}
		}
		runtime.KeepAlive(conns)
		b.StartTimer()
	}
	b.ReportMetric(float64(retained)/float64(b.N*count), "retained-B/relay")
}

func TestOrdinaryCountedConnDoesNotAdvertiseBufferedReads(t *testing.T) {
	sender, receiver := net.Pipe()
	defer sender.Close()
	_, conn := countedTestConn(t, receiver)
	defer conn.Close()
	if _, ok := conn.(netapi.BufferReader); ok {
		t.Fatal("ordinary connection advertised buffered reads")
	}
}

type partialRelayWriter struct{}

func (partialRelayWriter) Write([]byte) (int, error) { return 2, nil }

func TestCountedRelayCountsReadBytesOnWriteFailure(t *testing.T) {
	sender, receiver := pipe.Pipe()
	defer sender.Close()
	c, conn := countedTestConn(t, receiver)
	defer conn.Close()
	done := make(chan error, 1)
	go func() { _, err := sender.Write([]byte("payload")); done <- err }()
	n, err := relay.Copy(partialRelayWriter{}, conn)
	if n != 2 || !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("copy=%d/%v", n, err)
	}
	if got := c.Cache.LoadRunningDownload(); got != 7 {
		t.Fatalf("download=%d, want all read bytes", got)
	}
	_ = conn.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("partial write stranded sender")
	}
}

func quietRelayBenchmarkLogs(b *testing.B) {
	b.Helper()
	previous := log.Default()
	log.SetDefault(slog.NewTextHandler(io.Discard, nil))
	b.Cleanup(func() { log.SetDefault(previous) })
}

// Poison released buffers so an early Put is detected even when sync.Pool
// chooses not to reuse an allocation. Correctly owned buffers are untouched
// until their destination Write returns.
type poisoningRelayPool struct{ pool.Pool }

func (p poisoningRelayPool) PutBytes(b []byte) {
	for i := range b {
		b[i] = 0xa5
	}
	p.Pool.PutBytes(b)
}

type pausedRelayWriter struct {
	bytes.Buffer
	entered chan struct{}
	release chan struct{}
}

func (w *pausedRelayWriter) Write(p []byte) (int, error) {
	close(w.entered)
	<-w.release
	return w.Buffer.Write(p)
}

func TestCountedRelayKeepsBufferUntilWriteReturns(t *testing.T) {
	sender, receiver := pipe.Pipe()
	defer sender.Close()
	c, conn := countedTestConn(t, receiver)
	defer conn.Close()
	previous := pool.DefaultPool
	pool.DefaultPool = poisoningRelayPool{Pool: previous}
	defer func() { pool.DefaultPool = previous }()
	dst := &pausedRelayWriter{entered: make(chan struct{}), release: make(chan struct{})}
	done := make(chan error, 1)
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		_, err := relay.Copy(dst, conn)
		done <- err
	}()
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(dst.release) }) }
	defer func() { _ = conn.Close(); _ = sender.Close(); unblock(); <-stopped }()

	want := bytes.Repeat([]byte("original payload"), 64)
	source := bytes.Clone(want)
	if _, err := sender.Write(source); err != nil {
		t.Fatal(err)
	}
	// Write has acknowledged the source. The sender may now overwrite its
	// own slice while the relay's destination still holds the copied buffer.
	for i := range source {
		source[i] = 0x5a
	}
	<-dst.entered
	_ = receiver.Close() // Close the source while the destination is paused.
	var workers sync.WaitGroup
	for range 32 {
		workers.Go(func() {
			for range 32 {
				p := pool.GetBytes(16384)
				for i := range p {
					p[i] = 0x3c
				}
				pool.PutBytes(p)
			}
		})
	}
	workers.Wait()
	unblock()
	if err := <-done; !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("closed relay=%v", err)
	}
	if !bytes.Equal(dst.Bytes(), want) {
		t.Fatal("relay buffer overwritten before destination Write returned")
	}
	if got := c.Cache.LoadRunningDownload(); got != uint64(len(want)) {
		t.Fatalf("download=%d, want %d", got, len(want))
	}
}
