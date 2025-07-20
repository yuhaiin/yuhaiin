package websocket

import (
	"errors"
	"fmt"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestError(t *testing.T) {
	for _, v := range []struct {
		Check   error
		Target  error
		Matched bool
	}{
		{
			Check:   fmt.Errorf("mock err: %w", ErrBadStatus),
			Target:  ErrBadStatus,
			Matched: true,
		},
		{
			Check:   fmt.Errorf("mock err: %v", ErrBadStatus),
			Target:  ErrBadStatus,
			Matched: false,
		},
	} {
		assert.Equal(t, v.Matched, errors.Is(v.Check, v.Target))
	}
}
