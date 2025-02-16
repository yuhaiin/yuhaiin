package tls

import (
	"crypto/tls"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/pipe"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestSniffy(t *testing.T) {
	conn1, conn2 := pipe.Pipe()
	defer conn1.Close()
	defer conn2.Close()

	go func() {
		err := tls.Client(conn1, &tls.Config{
			ServerName: "test-ss",
		}).Handshake()
		t.Log(err)
	}()

	buf := make([]byte, 65535)

	n, err := conn2.Read(buf)
	assert.NoError(t, err)

	assert.Equal(t, "test-ss", Sniff(buf[:n]))
}
