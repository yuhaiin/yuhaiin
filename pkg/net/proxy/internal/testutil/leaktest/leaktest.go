package leaktest

import (
	"testing"

	"go.uber.org/goleak"
)

// VerifyNoGoroutineLeaks checks for goroutines left by a test after its cleanup
// functions have released protocol resources.
func VerifyNoGoroutineLeaks(t testing.TB) {
	t.Helper()
	t.Cleanup(func() { goleak.VerifyNone(t) })
}
