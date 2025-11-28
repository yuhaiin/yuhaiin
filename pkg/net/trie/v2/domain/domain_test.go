package domain

import (
	"strconv"
	"testing"
)

func TestDomainTrie(t *testing.T) {
	t.Run("InsertAndSearch", func(t *testing.T) {
		trieRoot := &trie[string]{Value: make(map[string]struct{})}

		insert(trieRoot, newFqdnReader("a.example.com"), "GroupA")
		got := search(trieRoot, newFqdnReader("a.example.com"))
		if !got.ContainsAll("GroupA") {
			t.Errorf("Expected GroupA, got %v", got)
		}

		insert(trieRoot, newFqdnReader("a.example.com"), "GroupB")
		got = search(trieRoot, newFqdnReader("a.example.com"))
		if !got.ContainsAll("GroupA", "GroupB") || got.Len() != 2 {
			t.Errorf("Expected GroupA and GroupB, got %v", got)
		}

		got = search(trieRoot, newFqdnReader("b.example.com"))
		if got.Len() != 0 {
			t.Errorf("Expected no match, got %v", got)
		}
	})

	t.Run("Wildcard", func(t *testing.T) {
		trieRoot := &trie[string]{Value: make(map[string]struct{})}

		insert(trieRoot, newFqdnReader("*.example.com"), "GroupWildcard")

		got := search(trieRoot, newFqdnReader("a.example.com"))
		if !got.ContainsAll("GroupWildcard") {
			t.Errorf("Expected GroupWildcard match, got %v", got)
		}

		got = search(trieRoot, newFqdnReader("b.example.com"))
		if !got.ContainsAll("GroupWildcard") {
			t.Errorf("Expected GroupWildcard match, got %v", got)
		}

		got = search(trieRoot, newFqdnReader("c.test.com"))
		if got.Len() != 0 {
			t.Errorf("Expected no match for c.test.com, got %v", got)
		}
	})

	t.Run("OverlappingRules", func(t *testing.T) {
		trieRoot := &trie[string]{Value: make(map[string]struct{})}

		insert(trieRoot, newFqdnReader("a.example.com"), "GroupA")
		insert(trieRoot, newFqdnReader("*.example.com"), "GroupWildcard")
		insert(trieRoot, newFqdnReader("a.example.com"), "GroupB")

		got := search(trieRoot, newFqdnReader("a.example.com"))
		if !got.ContainsAll("GroupA", "GroupB", "GroupWildcard") {
			t.Errorf("Expected all groups matched, got %v", got)
		}

		got = search(trieRoot, newFqdnReader("b.example.com"))
		if !got.ContainsAll("GroupWildcard") || got.Len() != 1 {
			t.Errorf("Expected only wildcard group, got %v", got)
		}
	})

	t.Run("Remove", func(t *testing.T) {
		trieRoot := &trie[string]{Value: make(map[string]struct{})}

		insert(trieRoot, newFqdnReader("a.example.com"), "GroupA")
		insert(trieRoot, newFqdnReader("a.example.com"), "GroupB")
		insert(trieRoot, newFqdnReader("*.example.com"), "GroupWildcard")

		remove(trieRoot, newFqdnReader("a.example.com"), "GroupA")
		got := search(trieRoot, newFqdnReader("a.example.com"))
		if !got.ContainsAll("GroupB", "GroupWildcard") || got.Len() != 2 {
			t.Errorf("Expected GroupB and GroupWildcard after remove GroupA, got %v", got)
		}

		remove(trieRoot, newFqdnReader("*.example.com"), "GroupWildcard")
		got = search(trieRoot, newFqdnReader("a.example.com"))
		if !got.ContainsAll("GroupB") || got.Len() != 1 {
			t.Errorf("Expected only GroupB after removing wildcard, got %v", got)
		}

		remove(trieRoot, newFqdnReader("a.example.com"), "GroupB")
		got = search(trieRoot, newFqdnReader("a.example.com"))
		if got.Len() != 0 {
			t.Errorf("Expected no match after removing all, got %v", got)
		}
	})

	t.Run("FullCoverage", func(t *testing.T) {
		trieRoot := &trie[string]{Value: make(map[string]struct{})}

		insert(trieRoot, newFqdnReader("a.example.com"), "Group1")
		insert(trieRoot, newFqdnReader("b.example.com"), "Group2")
		insert(trieRoot, newFqdnReader("*.example.com"), "GroupWildcard")
		insert(trieRoot, newFqdnReader("c.example.com"), "Group3")
		insert(trieRoot, newFqdnReader("c.example.com"), "Group4")

		got := search(trieRoot, newFqdnReader("a.example.com"))
		if !got.ContainsAll("Group1", "GroupWildcard") {
			t.Errorf("Expected Group1 and wildcard, got %v", got)
		}

		got = search(trieRoot, newFqdnReader("b.example.com"))
		if !got.ContainsAll("Group2", "GroupWildcard") {
			t.Errorf("Expected Group2 and wildcard, got %v", got)
		}

		got = search(trieRoot, newFqdnReader("c.example.com"))
		if !got.ContainsAll("Group3", "Group4", "GroupWildcard") {
			t.Errorf("Expected Group3, Group4, wildcard, got %v", got)
		}

		got = search(trieRoot, newFqdnReader("d.example.com"))
		if !got.ContainsAll("GroupWildcard") || got.Len() != 1 {
			t.Errorf("Expected only wildcard, got %v", got)
		}

		got = search(trieRoot, newFqdnReader("other.com"))
		if got.Len() != 0 {
			t.Errorf("Expected no match, got %v", got)
		}
	})
}

func BenchmarkDomainTrie(b *testing.B) {
	domains := make([]string, 1000)
	for i := range domains {
		domains[i] = "sub" + strconv.Itoa(i) + ".example.com"
	}

	b.Run("Insert", func(b *testing.B) {
		trieRoot := &trie[string]{Value: make(map[string]struct{})}
		b.ResetTimer()
		for i := 0; b.Loop(); i++ {
			insert(trieRoot, newFqdnReader(domains[i%len(domains)]), "benchmark")
		}
	})

	b.Run("Search", func(b *testing.B) {
		trieRoot := &trie[string]{Value: make(map[string]struct{})}
		for _, d := range domains {
			insert(trieRoot, newFqdnReader(d), "benchmark")
		}
		// Add a wildcard rule
		insert(trieRoot, newFqdnReader("*.example.com"), "wildcard")

		b.ResetTimer()
		for i := 0; b.Loop(); i++ {
			search(trieRoot, newFqdnReader(domains[i%len(domains)]))
		}
	})
}
