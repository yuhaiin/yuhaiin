package statistics

import (
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
)

func TestXxx(t *testing.T) {
	t.Log(toExtraMap(&netapi.Context{
		Source: netapi.ParseAddressPort(statistic.Type_tcp, "127.0.0.1", netapi.ParsePort(80)),
	}))
}
