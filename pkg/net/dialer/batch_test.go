package dialer

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestPacketConn(t *testing.T) {
	conn1, err := ListenPacketWithOptions("udp4", ":0", &Options{
		tryUpgradeToBatch: true,
	})
	assert.NoError(t, err)
	defer conn1.Close()

	conn2, err := ListenPacketWithOptions("udp4", ":0", &Options{
		tryUpgradeToBatch: true,
	})
	assert.NoError(t, err)
	defer conn2.Close()

	bc2 := conn2
	bc1 := conn1

	go func() {
		batches := make([]byte, 1024)

		for {
			n, addr, err := bc2.ReadFrom(batches)
			if err != nil {
				t.Error(err)
				break
			}

			t.Log(n, addr, string(batches[:n]))
		}
	}()

	_, err = bc1.WriteTo([]byte("hello world"+fmt.Sprint(10)), conn2.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Error(err)
	}

	_, err = bc1.WriteTo([]byte("hello world"+fmt.Sprint(11)), conn2.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Error(err)
	}
	time.Sleep(time.Second * 1)
}
