package statistics

import (
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

func TestXxx(t *testing.T) {
	t.Log(toExtraMap(&netapi.Context{
		Source: netapi.ParseAddressPort("tcp", "127.0.0.1", 80),
	}))
}
