package wireguard

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
	"github.com/tailscale/wireguard-go/conn"
)

func TestPacketConn(t *testing.T) {
	conn1, err := net.ListenPacket("udp4", ":0")
	assert.NoError(t, err)
	defer conn1.Close()

	conn2, err := net.ListenPacket("udp4", ":0")
	assert.NoError(t, err)
	defer conn2.Close()

	bc1 := NewIPv6Batch(128, conn1)
	bc2 := NewIPv6Batch(128, conn2)

	go func() {
		batches := make([][]byte, 10)
		for i := range batches {
			batches[i] = make([]byte, 2048)
		}
		size := make([]int, 10)
		endpoints := make([]conn.Endpoint, 10)
		for {
			n, err := bc2.ReadBatch(batches, size, endpoints)
			if err != nil {
				t.Error(err)
				break
			}

			t.Log(n)

			for i, v := range batches[:n] {
				t.Log(string(v[:size[i]]), size[i], endpoints[i])
			}
		}
	}()

	datas := make([][]byte, 10)
	for i := range datas {
		datas[i] = []byte("hello world" + fmt.Sprint(i))
	}

	err = bc1.WriteBatch(datas, conn2.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Error(err)
	}

	time.Sleep(time.Second * 3)
}
