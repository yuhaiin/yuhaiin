package pool

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

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
