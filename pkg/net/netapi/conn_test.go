package netapi

import (
	"io"
	"net"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
	"github.com/Asutorufa/yuhaiin/pkg/utils/relay"
)

func TestPrefixConn(t *testing.T) {
	conn1, _ := net.Pipe()
	conn1.Close()

	bytes := [][]byte{[]byte("a"), []byte("b"), []byte("c")}
	count := 0
	x := NewPrefixBytesConn(conn1, func(b []byte) {
		assert.MustEqual(t, bytes[count], b)
		count++
	}, bytes...)
	defer x.Close()

	_, _ = relay.Copy(io.Discard, x)
}
