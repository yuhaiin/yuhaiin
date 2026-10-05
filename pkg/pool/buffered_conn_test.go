package pool

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"
)

func TestGetBufioReaderDoesNotShareConnectionReader(t *testing.T) {
	// Pin the pool to one P so returning and borrowing the same reader is
	// deterministic, rather than relying on sync.Pool's scheduler behavior.
	previousProcs := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(previousProcs)
	previous := bufioBuffers[10]
	bufioBuffers[10] = &sync.Pool{New: func() any { return bufio.NewReaderSize(nil, 1024) }}
	defer func() { bufioBuffers[10] = previous }()

	c := NewBufferedConnSize(&dataErrorConn{}, 1024)
	defer c.Close()
	if err := c.BufioRead(func(r *bufio.Reader) error { _, err := r.Peek(1); return err }); err != nil {
		t.Fatal(err)
	}
	// The caller owns GetBufioReader's result and can return it independently
	// of the connection. Reusing it must not reset or overwrite c's prefix.
	borrowed := GetBufioReader(c, 1024)
	PutBufioReader(borrowed)
	reused := GetBufioReader(bytes.NewReader([]byte("overwritten")), 1024)
	defer PutBufioReader(reused)
	if _, err := reused.Peek(1); err != nil {
		t.Fatal(err)
	}
	var got [6]byte
	if _, err := io.ReadFull(c, got[:]); err != nil || string(got[:]) != "prefix" {
		t.Fatalf("connection prefix overwritten through pooled alias: %q/%v", got, err)
	}
}

func TestGetBufioReaderReadAheadIsPrivate(t *testing.T) {
	payload := []byte("private read-ahead")
	c := NewBufioConnSize(&readerTestConn{Reader: bytes.NewReader(payload)}, 1024)
	defer c.Close()
	r := GetBufioReader(c, 1024)
	defer PutBufioReader(r)
	if _, err := r.Peek(len(payload)); err != nil {
		t.Fatal(err)
	}
	var scratch [1]byte
	if n, err := c.Read(scratch[:]); n != 0 || err != io.EOF {
		t.Fatalf("connection must not expose the borrowed reader's prefix: %d/%v", n, err)
	}
	got, err := io.ReadAll(r)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("private read-ahead=%q/%v", got, err)
	}
}

func TestBufferedConnPreservesPrefixAndLaterBufferedReads(t *testing.T) {
	sender, receiver := net.Pipe()
	defer sender.Close()
	c := NewBufferedConnSize(receiver, 1024)
	defer c.Close()
	done := make(chan error, 1)
	go func() {
		_, err := sender.Write([]byte("prefix"))
		if err == nil {
			_, err = sender.Write([]byte("tail"))
		}
		done <- err
		_ = sender.Close()
	}()
	_ = c.SetDeadline(time.Now().Add(time.Second))
	if err := c.BufioRead(func(r *bufio.Reader) error {
		p, err := r.Peek(3)
		if !bytes.Equal(p, []byte("pre")) {
			t.Errorf("peek=%q", p)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"pr", "ef", "ix"} {
		var p [2]byte
		if _, err := io.ReadFull(c, p[:]); err != nil || string(p[:]) != want {
			t.Fatalf("prefix=%q/%v", p, err)
		}
	}
	// An empty read must not block after the prefix has drained.
	if n, err := c.Read(nil); n != 0 || err != nil {
		t.Fatalf("empty read=%d/%v", n, err)
	}
	if err := c.BufioRead(func(r *bufio.Reader) error {
		p, err := r.Peek(2)
		if string(p) != "ta" {
			t.Errorf("peek after drain=%q", p)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	p, err := io.ReadAll(c)
	if err != nil || string(p) != "tail" {
		t.Fatalf("tail=%q/%v", p, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	// Rewrapping a drained connection must keep its original ownership and
	// continue to report EOF rather than reuse an already pooled reader.
	if again := NewBufioConnSize(c, 512); again != c {
		t.Fatal("drained connection was wrapped again")
	}
	if err := c.BufioRead(func(r *bufio.Reader) error { _, err := r.ReadByte(); return err }); err != io.EOF {
		t.Fatalf("EOF=%v", err)
	}
}

func TestBufferedConnCloseInterruptsRead(t *testing.T) {
	sender, receiver := net.Pipe()
	defer sender.Close()
	started := make(chan struct{})
	c := NewBufferedConnSize(&readStartedConn{Conn: receiver, started: started}, 1024)
	done := make(chan error, 1)
	go func() { _, err := c.Read(make([]byte, 1)); done <- err }()
	select {
	case <-started:
	case <-time.After(time.Second):
		_ = c.Close()
		t.Fatal("read did not start")
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("read succeeded after close")
		}
	case <-time.After(time.Second):
		t.Fatal("close stranded read")
	}
	if err := c.BufioRead(func(*bufio.Reader) error { t.Error("closed callback invoked"); return nil }); err != io.EOF {
		t.Fatalf("closed buffered read=%v", err)
	}
}

type readStartedConn struct {
	net.Conn
	started chan struct{}
}

func (c *readStartedConn) Read(p []byte) (int, error) {
	close(c.started)
	return c.Conn.Read(p)
}

type dataErrorConn struct {
	net.Conn
	reads int
	err   error
}

func (c *dataErrorConn) Read(b []byte) (int, error) {
	c.reads++
	if c.reads == 1 {
		return copy(b, "prefix"), c.err
	}
	return copy(b, "tail"), io.EOF
}
func (c *dataErrorConn) Close() error { return nil }

func TestBufferedConnPreservesPendingReadError(t *testing.T) {
	for _, buffered := range []bool{false, true} {
		t.Run(fmt.Sprint(buffered), func(t *testing.T) {
			want := errors.New("read failure after prefix")
			c := NewBufferedConnSize(&dataErrorConn{err: want}, 1024)
			defer c.Close()
			if err := c.BufioRead(func(r *bufio.Reader) error { _, err := r.Peek(3); return err }); err != nil {
				t.Fatal(err)
			}
			var prefix [6]byte
			if _, err := io.ReadFull(c, prefix[:]); err != nil || string(prefix[:]) != "prefix" {
				t.Fatalf("prefix=%q/%v", prefix, err)
			}
			if buffered {
				// Merely inspecting the buffered length must not consume a pending error.
				if err := c.BufioRead(func(r *bufio.Reader) error {
					if r.Buffered() != 0 {
						t.Error("prefix not drained")
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				if err := c.BufioRead(func(r *bufio.Reader) error { _, err := r.ReadByte(); return err }); !errors.Is(err, want) {
					t.Fatalf("pending buffered error=%v, want %v", err, want)
				}
			} else {
				if n, err := c.Read(make([]byte, 1)); n != 0 || !errors.Is(err, want) {
					t.Fatalf("pending error=%d/%v, want %v", n, err, want)
				}
			}
			tail := make([]byte, 4)
			if n, err := c.Read(tail); n != 4 || string(tail) != "tail" || err != io.EOF {
				t.Fatalf("tail=%d/%q/%v", n, tail, err)
			}
		})
	}
}

func TestBufferedConnCanResumeOngoingBuffering(t *testing.T) {
	raw := &dataErrorConn{}
	c := NewBufferedConnSize(raw, 1024)
	defer c.Close()
	if err := c.BufioRead(func(r *bufio.Reader) error { _, err := r.Peek(1); return err }); err != nil {
		t.Fatal(err)
	}
	var prefix [6]byte
	if _, err := io.ReadFull(c, prefix[:]); err != nil {
		t.Fatal(err)
	}
	ongoing := NewBufioConnSize(c, 512)
	// An ordinary buffered connection must prefetch the remaining tail, so
	// several small reads do not each touch the underlying connection.
	for _, want := range []byte("tail") {
		var p [1]byte
		if n, err := ongoing.Read(p[:]); n != 1 || err != nil || p[0] != want {
			t.Fatalf("read=%d/%v/%q", n, err, p)
		}
	}
	if raw.reads != 2 {
		t.Fatalf("raw reads=%d, ongoing buffering was lost", raw.reads)
	}
}

type closeStartedConn struct {
	net.Conn
	started chan struct{}
	once    sync.Once
}

func (c *closeStartedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { close(c.started) })
	return err
}

func TestBufferedConnCloseDoesNotReleaseActiveCallback(t *testing.T) {
	sender, receiver := net.Pipe()
	defer sender.Close()
	closing := make(chan struct{})
	c := NewBufferedConnSize(&closeStartedConn{Conn: receiver, started: closing}, 1024)
	defer c.Close()
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	callbackDone := make(chan error, 1)
	callbackStopped, closeStopped := make(chan struct{}), make(chan struct{})
	go func() { _, _ = sender.Write([]byte("original")) }()
	go func() {
		defer close(callbackStopped)
		callbackDone <- c.BufioRead(func(r *bufio.Reader) error {
			p, err := r.Peek(8)
			close(entered)
			<-release
			if err == nil && string(p) != "original" {
				return fmt.Errorf("active callback buffer overwritten: %q", p)
			}
			return err
		})
	}()
	// Always unblock the callback before closing the connection on failure.
	defer func() { unblock(); <-callbackStopped; <-closeStopped }()
	<-entered
	go func() { defer close(closeStopped); _ = c.Close() }()
	<-closing
	select {
	case <-closeStopped:
		t.Error("Close returned while the callback owned the reader")
	default:
	}
	// Force other connections to fill pooled readers while Close is waiting.
	for range 128 {
		r := GetBufioReader(bytes.NewReader([]byte("overwritten")), 1024)
		_, _ = r.Peek(8)
		PutBufioReader(r)
	}
	unblock()
	if err := <-callbackDone; err != nil {
		t.Error(err)
	}
}

func TestBufferedConnConcurrentReadsPreserveData(t *testing.T) {
	payload := make([]byte, 256*1024)
	var want [256]int
	for i := range payload {
		payload[i] = byte((i*31 + i/256) % 256)
		want[payload[i]]++
	}
	c := NewBufferedConnSize(&readerTestConn{Reader: bytes.NewReader(payload)}, 1024)
	defer c.Close()
	if err := c.BufioRead(func(r *bufio.Reader) error { _, err := r.Peek(1); return err }); err != nil {
		t.Fatal(err)
	}
	type result struct {
		counts [256]int
		err    error
	}
	done := make(chan result, 16)
	for range cap(done) {
		go func() {
			var out result
			buf := make([]byte, 97)
			for {
				n, err := c.Read(buf)
				for _, b := range buf[:n] {
					out.counts[b]++
				}
				if err != nil {
					if err != io.EOF {
						out.err = err
					}
					done <- out
					return
				}
			}
		}()
	}
	var got [256]int
	for range cap(done) {
		out := <-done
		if out.err != nil {
			t.Error(out.err)
		}
		for i, n := range out.counts {
			got[i] += n
		}
	}
	if got != want {
		t.Fatal("concurrent reads lost, duplicated, or overwrote bytes")
	}
}

type readerTestConn struct {
	net.Conn
	io.Reader
}

func (c *readerTestConn) Read(p []byte) (int, error) { return c.Reader.Read(p) }
func (c *readerTestConn) Close() error               { return nil }
