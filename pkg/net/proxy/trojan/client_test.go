package trojan

import (
	"bytes"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/tools"
)

func TestXxx(t *testing.T) {
	b := bytes.NewBuffer(nil)

	tools.EncodeAddr(netapi.ParseAddressPort(0, "www.baidu.com", netapi.EmptyPort), b)
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
