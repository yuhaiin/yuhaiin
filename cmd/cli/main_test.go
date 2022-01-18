package main

import (
	"strconv"
	"testing"
)

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

func TestParse(t *testing.T) {
	z := "65535"

	t.Log(strconv.ParseUint(z, 10, 16))
	t.Log(strconv.FormatUint(65535, 10))
}
