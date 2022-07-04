package yerror

import (
	"fmt"
	"net"
	"testing"
)

func TestTo(t *testing.T) {
	var r error = &net.OpError{}

	r = fmt.Errorf("wrap: %w", r)
	r = fmt.Errorf("wrap: %w", r)

	if z, ok := To[net.Error](r); ok {
		t.Log(z.Timeout())
	}
}
