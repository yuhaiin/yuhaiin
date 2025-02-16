package pipe

import (
	"net"
	"sync"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
	"golang.org/x/net/nettest"
)

func TestPipe(t *testing.T) {
	t.Run("test pipe", func(t *testing.T) {
		nettest.TestConn(t, func() (c1 net.Conn, c2 net.Conn, stop func(), err error) {
			c1, c2 = Pipe()

			return c1, c2, func() {
				c1.Close()
				c2.Close()
			}, nil
		})
	})

	t.Run("close write", func(t *testing.T) {
		c1, c2 := Pipe()

		err := c1.CloseWrite()
		assert.NoError(t, err)

		buf := make([]byte, 1024)

		wg := sync.WaitGroup{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			n, err := c1.Read(buf)
			assert.NoError(t, err)
			buf = buf[:n]
		}()

		_, err = c2.Write([]byte("hello"))
		assert.NoError(t, err)

		wg.Wait()

		assert.Equal(t, string(buf), "hello")

		_, err = c1.Write([]byte("world"))
		assert.Error(t, err)
	})
}
