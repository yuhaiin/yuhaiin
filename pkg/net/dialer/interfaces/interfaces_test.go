package interfaces

import (
	"testing"
)

func TestGetLocalAddress(t *testing.T) {
	t.Log(LocalAddresses())
}
