package kvjson

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// fileLock represents a lock on a file, using PID to detect stale locks.
type fileLock struct {
	path string
	file *os.File
	pid  int
}

// acquireLock tries to acquire a file lock in a loop with context support.
// It uses O_CREATE|O_EXCL to create the lock file atomically.
// If the lock file already exists, it checks whether the previous owner process is alive.
// If the previous owner is dead, it removes the stale lock and retries.
// The function respects context cancellation and timeout.
func acquireLock(ctx context.Context, path string) (*fileLock, error) {
	pid := os.Getpid()
	backoff := 50 * time.Millisecond
	maxBackoff := 500 * time.Millisecond

	for {
		// 1. Try to create the lock file atomically
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0644)
		if err == nil {
			// Write current PID into the lock file
			_, _ = fmt.Fprintf(f, "%d\n", pid)
			return &fileLock{
				path: path,
				file: f,
				pid:  pid,
			}, nil
		}

		// If the error is not "file exists", return it
		if !errors.Is(err, os.ErrExist) {
			return nil, err
		}

		// 2. Lock file exists, check if it is stale
		data, err := os.ReadFile(path)
		if err == nil {
			oldPID, err := strconv.Atoi(strings.TrimSpace(string(data)))
			// If PID is invalid or process is dead, remove stale lock and retry
			if err != nil || !processAlive(oldPID) {
				_ = os.Remove(path)
				continue
			}
		}

		// 3. Wait with backoff or return if context is done
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(backoff):
		}

		// 4. Exponential backoff with cap
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

// release releases the lock by closing the file and removing it.
func (l *fileLock) release() error {
	_ = l.file.Close()
	return os.Remove(l.path)
}

// processAlive checks whether a process with given PID is still running.
// It returns true if the process exists, false otherwise.
func processAlive(pid int) bool {
	_, err := os.Stat(fmt.Sprintf("/proc/%d", pid))
	return err == nil
}
