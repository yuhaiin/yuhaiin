package permission

import "testing"

func TestCatalogIsCompleteAndDefensivelyCopied(t *testing.T) {
	catalog := Catalog()
	values := Values()
	if len(catalog) == 0 || len(catalog) != len(values) {
		t.Fatalf("catalog has %d definitions and %d values", len(catalog), len(values))
	}
	seen := make(map[Permission]bool, len(catalog))
	for i, definition := range catalog {
		if definition.ID == "" || definition.Category == "" || definition.Description == "" {
			t.Errorf("incomplete permission definition at index %d: %+v", i, definition)
		}
		if seen[definition.ID] {
			t.Errorf("duplicate permission ID %q", definition.ID)
		}
		seen[definition.ID] = true
		if values[i] != definition.ID {
			t.Errorf("value at index %d is %q, want %q", i, values[i], definition.ID)
		}
	}
	catalog[0].Description = "changed"
	values[0] = "changed"
	if got := Catalog()[0].Description; got == "changed" {
		t.Fatal("Catalog returned mutable internal state")
	}
	if got := Values()[0]; got == "changed" {
		t.Fatal("Values returned mutable internal state")
	}
}
