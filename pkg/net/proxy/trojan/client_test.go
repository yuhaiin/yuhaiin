package trojan

import (
	"bytes"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/tools"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestXxx(t *testing.T) {
	b := bytes.NewBuffer(nil)

	ba, err := netapi.ParseAddressPort("", "www.baidu.com", 0)
	assert.NoError(t, err)
	tools.WriteAddr(ba, b)
	size := b.Len()

	b.Write([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11})
	// for b.Len() > 0 {
	// 	z := b.Next(399)

	// 	t.Log(len(z), z)
	// }

	b.Truncate(size)
	b.Write([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11})
	t.Log(b.Bytes())
}
