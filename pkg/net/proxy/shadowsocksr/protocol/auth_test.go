package protocol

import (
	"crypto/rand"
	"testing"
)

func TestRead(t *testing.T) {
	z := make([]byte, 10)

	rand.Read(z[2:6])
	t.Log(z)
}
