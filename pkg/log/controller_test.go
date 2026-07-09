package log

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	contractsettings "github.com/Asutorufa/yuhaiin/pkg/contract/settings"
)

func TestTailSnapshotAndBroadcast(t *testing.T) {
	ctr := NewController()
	defer func() {
		if err := ctr.Close(); err != nil {
			t.Error(err)
		}
	}()

	OutputStderr.Store(false)
	defer OutputStderr.Store(true)

	ctr.Set(contractsettings.Logcat{Save: true, Level: "debug"}, filepath.Join(t.TempDir(), "test.log"))

	Info("before tail", "i", 1)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logs := make(chan string, 16)
	errs := make(chan error, 1)
	go func() {
		errs <- ctr.Tail(ctx, func(line []string) error {
			for _, l := range line {
				logs <- l
				if strings.Contains(l, "after tail") {
					cancel()
				}
			}

			return nil
		})
	}()

	waitLog(t, logs, "before tail")

	Info("after tail", "i", 2)
	waitLog(t, logs, "after tail")

	if err := <-errs; err != nil {
		t.Fatal(err)
	}
}

func TestTailReturnsCallbackError(t *testing.T) {
	ctr := NewController()
	defer func() {
		if err := ctr.Close(); err != nil {
			t.Error(err)
		}
	}()

	OutputStderr.Store(false)
	defer OutputStderr.Store(true)

	ctr.Set(contractsettings.Logcat{Save: true, Level: "debug"}, filepath.Join(t.TempDir(), "test.log"))

	Info("callback error")

	errExpected := errors.New("callback failed")
	err := ctr.Tail(context.Background(), func(line []string) error {
		return errExpected
	})
	if !errors.Is(err, errExpected) {
		t.Fatalf("expected %v, got %v", errExpected, err)
	}
}

func TestTailReadsLongLine(t *testing.T) {
	ctr := NewController()
	defer func() {
		if err := ctr.Close(); err != nil {
			t.Error(err)
		}
	}()

	OutputStderr.Store(false)
	defer OutputStderr.Store(true)

	ctr.Set(contractsettings.Logcat{Save: true, Level: "debug"}, filepath.Join(t.TempDir(), "test.log"))

	msg := strings.Repeat("x", 2048)
	Info(msg)

	errDone := errors.New("done")
	err := ctr.Tail(context.Background(), func(line []string) error {
		if len(line) != 1 {
			t.Fatalf("expected one line, got %d: %v", len(line), line)
		}
		if !strings.Contains(line[0], msg) {
			t.Fatalf("tail line does not contain full log message")
		}

		return errDone
	})
	if !errors.Is(err, errDone) {
		t.Fatalf("expected %v, got %v", errDone, err)
	}
}

func waitLog(t *testing.T, logs <-chan string, want string) {
	t.Helper()

	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()

	for {
		select {
		case line := <-logs:
			if strings.Contains(line, want) {
				return
			}
		case <-timer.C:
			t.Fatalf("timeout waiting for log containing %q", want)
		}
	}
}
