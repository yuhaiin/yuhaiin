package helper

import "testing"

func TestOutdated(t *testing.T) {
	for _, c := range []struct {
		service, ours string
		want          bool
	}{
		{"v1+abc", "v1+abc", false},
		{"v1+abc", "v2+def", true},
		{"", "v2+def", true}, // a service from before versions were reported
		{"v1", "", false},
	} {
		if got := outdated(c.service, c.ours); got != c.want {
			t.Errorf("outdated(%q, %q) = %v", c.service, c.ours, got)
		}
	}
	if BuildID() == "" {
		t.Fatal("empty build id")
	}
}
