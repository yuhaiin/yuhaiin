package diskio

import (
	"bytes"
	"errors"
	"io"
	"os"
	"testing"
)

type countingWriter struct {
	file  *os.File
	calls int
}

func (w *countingWriter) WriteAt(data []byte, offset int64) (int, error) {
	w.calls++
	return w.file.WriteAt(data, offset)
}

func TestWriterCoalescesAndPreservesGaps(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "output")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	want := bytes.Repeat([]byte{0xff}, 2*BufferSize+100)
	if _, err := f.Write(want); err != nil {
		t.Fatal(err)
	}
	counter := &countingWriter{file: f}
	writer := NewWriterAt(counter)
	for i := range 1000 {
		data := []byte{byte(i), 0, 1, 2}
		offset := 17 + i*4
		if _, err := writer.WriteAt(data, int64(offset)); err != nil {
			t.Fatal(err)
		}
		copy(want[offset:], data)
	}
	for _, offset := range []int{17, 20, 5000, 4999, BufferSize, 2 * BufferSize} {
		if _, err := writer.WriteAt([]byte("patch"), int64(offset)); err != nil {
			t.Fatal(err)
		}
		copy(want[offset:], "patch")
	}
	large := bytes.Repeat([]byte{0x55}, BufferSize)
	if _, err := writer.WriteAt(large, 5000); err != nil {
		t.Fatal(err)
	}
	copy(want[5000:], large)
	if err := writer.Flush(); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("buffering changed unwritten bytes or lost a patch")
	}
	if counter.calls >= 10 {
		t.Fatalf("%d writes, want fewer than 10", counter.calls)
	}
}

type failedWriter struct{ err error }

func (w failedWriter) WriteAt([]byte, int64) (int, error) { return 0, w.err }

func TestWriterPropagatesFailures(t *testing.T) {
	for _, failure := range []error{nil, os.ErrPermission} {
		writer := NewWriterAt(failedWriter{failure})
		if _, err := writer.WriteAt([]byte("small"), 0); err != nil {
			t.Fatal(err)
		}
		want := failure
		if want == nil {
			want = io.ErrShortWrite
		}
		if err := writer.Flush(); !errors.Is(err, want) {
			t.Fatalf("Flush = %v, want %v", err, want)
		}
		if _, err := writer.WriteAt([]byte("seek"), BufferSize); !errors.Is(err, want) {
			t.Fatalf("seek = %v, want %v", err, want)
		}
		large := NewWriterAt(failedWriter{failure})
		if _, err := large.WriteAt(make([]byte, BufferSize), 0); !errors.Is(err, want) {
			t.Fatalf("large write = %v, want %v", err, want)
		}
	}
}
