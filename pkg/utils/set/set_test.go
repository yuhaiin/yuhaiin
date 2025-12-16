package set

import "testing"

func TestEmptySet(t *testing.T) {
	t.Log(EmptyImmutableSet[string]())

}
