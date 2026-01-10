package domain

import (
	"slices"
	"strconv"
	"testing"
)

func TestDomainTrie(t *testing.T) {
	t.Run("test not match", func(t *testing.T) {
		trieRoot := &trie[string]{Value: make([]string, 0)}
		insert(trieRoot, newFqdnReader("redirector.c.play.google.com"), "GroupA")
		got := search(trieRoot, newFqdnReader("play.google.com"))
		if len(got) != 0 {
			t.Errorf("Expected no match, got %v", got)
		}
	})

	t.Run("InsertAndSearch", func(t *testing.T) {
		trieRoot := &trie[string]{Value: make([]string, 0)}

		insert(trieRoot, newFqdnReader("a.example.com"), "GroupA")
		got := search(trieRoot, newFqdnReader("a.example.com"))
		if !slices.Contains(got, "GroupA") {
			t.Errorf("Expected GroupA, got %v", got)
		}

		insert(trieRoot, newFqdnReader("a.example.com"), "GroupB")
		got = search(trieRoot, newFqdnReader("a.example.com"))
		if !slices.Contains(got, "GroupA") || !slices.Contains(got, "GroupB") || len(got) != 2 {
			t.Errorf("Expected GroupA and GroupB, got %v", got)
		}

		got = search(trieRoot, newFqdnReader("b.example.com"))
		if len(got) != 0 {
			t.Errorf("Expected no match, got %v", got)
		}
	})

	t.Run("wildcard2", func(t *testing.T) {
		trieRoot := &trie[string]{Value: make([]string, 0)}

		insert(trieRoot, newFqdnReader("*.example.com"), "GroupWildcard")

		got := search(trieRoot, newFqdnReader("a.example.com"))
		if !slices.Contains(got, "GroupWildcard") {
			t.Errorf("Expected GroupWildcard match, got %v", got)
		}

		got = search(trieRoot, newFqdnReader("example.com"))
		if !slices.Contains(got, "GroupWildcard") {
			t.Errorf("Expected GroupWildcard match, got %v", got)
		}
	})

	t.Run("Wildcard", func(t *testing.T) {
		trieRoot := &trie[string]{Value: make([]string, 0)}

		insert(trieRoot, newFqdnReader("*.example.com"), "GroupWildcard")
		insert(trieRoot, newFqdnReader("a.example.*"), "GroupWildcard2")
		insert(trieRoot, newFqdnReader("*.example.*"), "GroupWildcard3")

		got := search(trieRoot, newFqdnReader("a.example.com"))
		if !slices.Contains(got, "GroupWildcard") {
			t.Errorf("Expected GroupWildcard match, got %v", got)
		}

		got = search(trieRoot, newFqdnReader("a.example.test"))
		if !slices.Contains(got, "GroupWildcard2") {
			t.Errorf("Expected GroupWildcard2 match, got %v", got)
		}

		got = search(trieRoot, newFqdnReader("b.example.com"))
		if !slices.Contains(got, "GroupWildcard") {
			t.Errorf("Expected GroupWildcard match, got %v", got)
		}

		got = search(trieRoot, newFqdnReader("b.example.test"))
		if !slices.Contains(got, "GroupWildcard3") {
			t.Errorf("Expected GroupWildcard3 match, got %v", got)
		}

		got = search(trieRoot, newFqdnReader("c.test.com"))
		if len(got) != 0 {
			t.Errorf("Expected no match for c.test.com, got %v", got)
		}
	})

	t.Run("OverlappingRules", func(t *testing.T) {
		trieRoot := &trie[string]{Value: make([]string, 0)}

		insert(trieRoot, newFqdnReader("a.example.com"), "GroupA")
		insert(trieRoot, newFqdnReader("*.example.com"), "GroupWildcard")
		insert(trieRoot, newFqdnReader("a.example.com"), "GroupB")

		got := search(trieRoot, newFqdnReader("a.example.com"))
		if !slices.Contains(got, "GroupA") || !slices.Contains(got, "GroupB") || !slices.Contains(got, "GroupWildcard") || len(got) != 3 {
			t.Errorf("Expected all groups matched, got %v", got)
		}

		got = search(trieRoot, newFqdnReader("b.example.com"))
		if !slices.Contains(got, "GroupWildcard") || len(got) != 1 {
			t.Errorf("Expected only wildcard group, got %v", got)
		}
	})

	t.Run("Remove", func(t *testing.T) {
		trieRoot := &trie[string]{Value: make([]string, 0)}

		insert(trieRoot, newFqdnReader("a.example.com"), "GroupA")
		insert(trieRoot, newFqdnReader("a.example.com"), "GroupB")
		insert(trieRoot, newFqdnReader("*.example.com"), "GroupWildcard")

		remove(trieRoot, newFqdnReader("a.example.com"), "GroupA")
		got := search(trieRoot, newFqdnReader("a.example.com"))
		if !slices.Contains(got, "GroupB") || !slices.Contains(got, "GroupWildcard") || len(got) != 2 {
			t.Errorf("Expected GroupB and GroupWildcard after remove GroupA, got %v", got)
		}

		remove(trieRoot, newFqdnReader("*.example.com"), "GroupWildcard")
		got = search(trieRoot, newFqdnReader("a.example.com"))
		if !slices.Contains(got, "GroupB") || len(got) != 1 {
			t.Errorf("Expected only GroupB after removing wildcard, got %v", got)
		}

		remove(trieRoot, newFqdnReader("a.example.com"), "GroupB")
		got = search(trieRoot, newFqdnReader("a.example.com"))
		if len(got) != 0 {
			t.Errorf("Expected no match after removing all, got %v", got)
		}
	})

	t.Run("FullCoverage", func(t *testing.T) {
		trieRoot := &trie[string]{Value: make([]string, 0)}

		insert(trieRoot, newFqdnReader("a.example.com"), "Group1")
		insert(trieRoot, newFqdnReader("b.example.com"), "Group2")
		insert(trieRoot, newFqdnReader("*.example.com"), "GroupWildcard")
		insert(trieRoot, newFqdnReader("c.example.com"), "Group3")
		insert(trieRoot, newFqdnReader("c.example.com"), "Group4")

		got := search(trieRoot, newFqdnReader("a.example.com"))
		if !slices.Contains(got, "Group1") || !slices.Contains(got, "GroupWildcard") || len(got) != 2 {
			t.Errorf("Expected Group1 and wildcard, got %v", got)
		}

		got = search(trieRoot, newFqdnReader("b.example.com"))
		if !slices.Contains(got, "Group2") || !slices.Contains(got, "GroupWildcard") || len(got) != 2 {
			t.Errorf("Expected Group2 and wildcard, got %v", got)
		}

		got = search(trieRoot, newFqdnReader("c.example.com"))
		if !slices.Contains(got, "Group3") || !slices.Contains(got, "Group4") || !slices.Contains(got, "GroupWildcard") || len(got) != 3 {
			t.Errorf("Expected Group3, Group4, wildcard, got %v", got)
		}

		got = search(trieRoot, newFqdnReader("d.example.com"))
		if !slices.Contains(got, "GroupWildcard") || len(got) != 1 {
			t.Errorf("Expected only wildcard, got %v", got)
		}

		got = search(trieRoot, newFqdnReader("other.com"))
		if len(got) != 0 {
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
		trieRoot := &trie[string]{Value: make([]string, 0)}
		b.ResetTimer()
		for i := 0; b.Loop(); i++ {
			insert(trieRoot, newFqdnReader(domains[i%len(domains)]), "benchmark")
		}
	})

	b.Run("Search", func(b *testing.B) {
		trieRoot := &trie[string]{Value: make([]string, 0)}
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
