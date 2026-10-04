package pipe

import (
	"bytes"
	"errors"
	"io"
	"os"
	"testing"
	"time"
)

func TestReadWithBufferCopiesBeforeAcknowledging(t *testing.T) {
	sender, receiver := Pipe()
	defer sender.Close()
	defer receiver.Close()
	data := []byte("original")
	started, release, written := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(written)
		_, _ = sender.Write(data)
		copy(data, "modified")
		_ = sender.CloseWrite()
	}()
	result := make(chan []byte, 1)
	go func() {
		buf, _ := receiver.ReadWithBuffer(func() []byte { close(started); <-release; return make([]byte, 32) })
		result <- buf
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("buffer was not requested")
	}
	select {
	case <-written:
		t.Fatal("sender returned before its data was copied")
	default:
	}
	close(release)
	buf := <-result
	<-written
	if string(buf) != "original" {
		t.Fatalf("corrupted buffer: %q", buf)
	}
}

func TestReadWithBufferHalfCloseAndChunking(t *testing.T) {
	sender, receiver := Pipe()
	defer sender.Close()
	defer receiver.Close()
	done := make(chan struct{})
	go func() { defer close(done); _, _ = sender.Write([]byte("request")); _ = sender.CloseWrite() }()
	var output bytes.Buffer
	scratch := make([]byte, 3)
	for {
		data, err := receiver.ReadWithBuffer(func() []byte { return scratch })
		output.Write(data)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	<-done
	if output.String() != "request" {
		t.Fatalf("copy=%s", output.String())
	}
	go func() { _, _ = receiver.Write([]byte("response")); _ = receiver.CloseWrite() }()
	data, err := io.ReadAll(sender)
	if err != nil || string(data) != "response" {
		t.Fatalf("reverse=%q/%v", data, err)
	}
}

func TestReadWithBufferDoesNotAcquireBufferWhileIdle(t *testing.T) {
	for _, action := range []string{"deadline", "close", "remoteClose"} {
		t.Run(action, func(t *testing.T) {
			sender, receiver := Pipe()
			defer sender.Close()
			defer receiver.Close()
			done := make(chan error, 1)
			called := make(chan struct{}, 1)
			go func() {
				_, err := receiver.ReadWithBuffer(func() []byte { called <- struct{}{}; return make([]byte, 16) })
				done <- err
			}()
			switch action {
			case "deadline":
				_ = receiver.SetReadDeadline(time.Now().Add(-time.Second))
			case "close":
				_ = receiver.Close()
			case "remoteClose":
				_ = sender.Close()
			}
			select {
			case err := <-done:
				if action == "deadline" && !errors.Is(err, os.ErrDeadlineExceeded) {
					t.Fatalf("deadline=%v", err)
				}
				if action == "close" && !errors.Is(err, io.ErrClosedPipe) {
					t.Fatalf("close=%v", err)
				}
				if action == "remoteClose" && !errors.Is(err, io.EOF) {
					t.Fatalf("EOF=%v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("read did not wake up")
			}
			select {
			case <-called:
				t.Fatal("idle read acquired a buffer")
			default:
			}
		})
	}
}

func TestReadWithBufferPanicAcknowledgesWriter(t *testing.T) {
	sender, receiver := Pipe()
	defer sender.Close()
	defer receiver.Close()
	done := make(chan struct{})
	go func() { defer close(done); _, _ = sender.Write([]byte("payload")) }()
	func() {
		defer func() {
			if recover() == nil {
				t.Error("missing panic")
			}
		}()
		_, _ = receiver.ReadWithBuffer(func() []byte { panic("acquire buffer") })
	}()
	_ = receiver.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("writer stranded on ack")
	}
}
