package set

import (
	"sync"
	"testing"
)

func TestEmptySet(t *testing.T) {
	s1 := EmptyImmutableSet[string]()
	s2 := EmptyImmutableSet[string]()
	if s1 != s2 {
		t.Errorf("expected same empty set instance for the same type, got %p and %p", s1, s2)
	}

	i1 := EmptyImmutableSet[int]()
	if any(s1) == any(i1) {
		t.Error("expected different empty set instances for different types")
	}

	// Test for concurrency safety (the race detector will find issues)
	var wg sync.WaitGroup
	const numGoroutines = 100
	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			_ = EmptyImmutableSet[int]()
			_ = EmptyImmutableSet[string]()
		}()
	}
	wg.Wait()
}
