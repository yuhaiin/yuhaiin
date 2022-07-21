package ssr

import "testing"

func TestKDF(t *testing.T) {
	t.Log(KDF("12345678", 16))
}
