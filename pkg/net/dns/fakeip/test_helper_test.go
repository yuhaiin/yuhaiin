package fakeip

import (
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/cache/memory"
)

func NewMemCache(tb testing.TB) *memory.MemoryCache {
	tb.Helper()
	return memory.NewMemoryCache()
}
