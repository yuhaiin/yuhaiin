package tls

import (
	"crypto/tls"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/pipe"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestSniffy(t *testing.T) {
	conn1, conn2 := pipe.Pipe()
	done := make(chan struct{})
	defer func() {
		_ = conn1.Close()
		_ = conn2.Close()
		<-done
	}()
	go func() {
		defer close(done)
		_ = tls.Client(conn1, &tls.Config{
			ServerName: "test-ss",
		}).Handshake()
	}()

	buf := make([]byte, 65535)

	n, err := conn2.Read(buf)
	assert.NoError(t, err)

	assert.Equal(t, "test-ss", Sniff(buf[:n]))
}
