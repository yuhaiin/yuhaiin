package relay

import (
	"bytes"
	"errors"
	"github.com/Asutorufa/yuhaiin/pkg/net/pipe"
	"io"
	"os"
	"syscall"
	"testing"
	"time"
)

func TestErrIs(t *testing.T) {
	reset := &os.SyscallError{
		Err:     syscall.ECONNRESET,
		Syscall: "connect",
	}

	if !errors.Is(reset, syscall.ECONNRESET) {
		t.Fatal("not equal")
	}

	t.Log(reset)
}

func TestPipeCopyPanicDoesNotStrandSender(t *testing.T) {
	sender, receiver := pipe.Pipe()
	defer sender.Close()
	defer receiver.Close()
	done := make(chan struct{})
	go func() { defer close(done); _, _ = sender.Write([]byte("payload")) }()
	if _, err := Copy(panicWriter{}, receiver); err == nil {
		t.Fatal("panic was not reported")
	}
	_ = receiver.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("panic stranded sender on acknowledgment")
	}
}

type panicWriter struct{}

func (panicWriter) Write([]byte) (int, error) { panic("test panic") }

type failingWriter struct {
	count int
	err   error
}

func (w failingWriter) Write([]byte) (int, error) { return w.count, w.err }
func TestPipeCopyWriterErrors(t *testing.T) {
	want := errors.New("write failure")
	for _, tc := range []struct {
		name   string
		writer failingWriter
		want   error
		n      int64
	}{
		{"error", failingWriter{0, want}, want, 0},
		{"partial", failingWriter{2, nil}, io.ErrShortWrite, 2},
		{"invalid", failingWriter{-1, nil}, nil, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sender, receiver := pipe.Pipe()
			defer sender.Close()
			defer receiver.Close()
			done := make(chan struct{})
			go func() { defer close(done); _, _ = sender.Write([]byte("payload")) }()
			n, err := Copy(tc.writer, receiver)
			if err == nil || n != tc.n || (tc.want != nil && !errors.Is(err, tc.want)) {
				t.Fatalf("Copy=%d/%v", n, err)
			}
			_ = receiver.Close()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("writer stranded")
			}
		})
	}
}

type terminalBufferReader struct {
	data []byte
	err  error
}

func (r terminalBufferReader) Read([]byte) (int, error) { panic("buffered read capability lost") }
func (r terminalBufferReader) ReadWithBuffer(get func() []byte) ([]byte, error) {
	buf := get()
	n := copy(buf, r.data)
	return buf[:n], r.err
}

func TestBufferReaderCopiesDataBeforeTerminalError(t *testing.T) {
	failure := errors.New("read failure")
	for _, terminal := range []error{io.EOF, failure} {
		var dst bytes.Buffer
		n, err := Copy(&dst, terminalBufferReader{data: []byte("last chunk"), err: terminal})
		want := terminal
		if terminal == io.EOF {
			want = nil
		}
		if n != 10 || dst.String() != "last chunk" || !errors.Is(err, want) {
			t.Fatalf("copy=%d/%v/%q", n, err, dst.String())
		}
	}
}
