package reject

import (
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestReject(t *testing.T) {
	r := NewReject(5, 15)

	addr, err := netapi.ParseAddressPort("", "www.baidu.com", 0)
	assert.NoError(t, err)
	z := time.Millisecond * 300
	for {
		if z >= time.Second*10 {
			break
		}

		t.Log(r.(*reject).delay(addr))

		// time.Sleep(time.Second)
		// z += time.Microsecond * 500
	}
}
