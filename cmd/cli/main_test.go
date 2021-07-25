package main

import "testing"

func TestSet(t *testing.T) {
	s := map[string]interface{}{
		"a": map[string]interface{}{
			"b": map[string]interface{}{
				"c": false,
			},
		},
		"d": "d",
	}
	t.Log(s)

	set(s, []string{"a", "b", "c"}, "true")

	t.Log(s)
}
