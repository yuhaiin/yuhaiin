package dialer

import (
	"context"
	"fmt"
	"net"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestError(t *testing.T) {
	x := &net.OpError{
		Op:   "block",
		Net:  "tcp",
		Addr: netapi.EmptyAddr,
		Err:  net.UnknownNetworkError("unknown network"),
	}

	y := fmt.Errorf("x: %w", x)

	assert.Equal(t, netapi.IsBlockError(y), true)
}

func TestDial8305(t *testing.T) {
	add, err := netapi.ParseDomainPort("tcp", "www.google.com", 443)
	assert.NoError(t, err)
	conn, err := DialHappyEyeballsv2(context.TODO(), add)
	assert.NoError(t, err)
	defer conn.Close()
	t.Log(conn.LocalAddr(), conn.RemoteAddr())
}
