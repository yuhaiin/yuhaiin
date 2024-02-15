package vision

import (
	"crypto/tls"
	"io"
	"net"
	"os"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestVision(t *testing.T) {
	s, err := net.Listen("tcp", "127.0.0.1:32123")
	assert.NoError(t, err)

	go func() {
		for {
			conn, err := s.Accept()
			if err != nil {
				t.Error(err)
				break
			}

			tlsConn := tls.Server(conn, &tls.Config{})

			go func() {
				visionConn, err := NewVisionConn(conn, tlsConn, [16]byte{})
				if err != nil {
					t.Error(err)
				}
				defer visionConn.Close()

				buf := make([]byte, 1024)

				n, err := visionConn.Read(buf)
				if err != nil {
					t.Error(err)
				}

				t.Log(n, string(buf[:n]), "end")

				n, err = visionConn.Write(buf[:n])
				if err != nil {
					t.Error(err)
				}

				t.Log(n)
			}()
		}
	}()

	conn, err := net.Dial("tcp", "127.0.0.1:32123")
	assert.NoError(t, err)

	tlsConn := tls.Client(conn, &tls.Config{})

	vconn, err := NewVisionConn(conn, tlsConn, [16]byte{})
	assert.NoError(t, err)

	_, err = vconn.Write([]byte("Hello World!"))
	assert.NoError(t, err)

	n, err := io.Copy(os.Stdout, vconn)
	assert.NoError(t, err)

	t.Log(n)
}
