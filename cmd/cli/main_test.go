package main

import (
	"strconv"
	"testing"
)

func TestParse(t *testing.T) {
	z := "65535"

	t.Log(strconv.ParseUint(z, 10, 16))
	t.Log(strconv.FormatUint(65535, 10))
}
