package mixed

import (
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

func TestNoneClose(t *testing.T) {
	var x *netapi.ChannelListener
	noneNilClose(x)
}
