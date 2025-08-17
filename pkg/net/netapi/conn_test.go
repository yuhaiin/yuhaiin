package netapi

import (
	"fmt"
	"net"
	"os"
	"syscall"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestTimedout(t *testing.T) {
	e := &os.SyscallError{
		Err: syscall.ETIMEDOUT,
	}

	assert.Equal(t, true, IsConnectionTimedout(fmt.Errorf("t: %w", &net.OpError{Err: e})))
}
