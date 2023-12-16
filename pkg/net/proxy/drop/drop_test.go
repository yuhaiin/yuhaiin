package drop

import (
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

func TestDrop(t *testing.T) {
	time := Drop.waitTime(netapi.EmptyAddr)
	t.Log(time)
	time = Drop.waitTime(netapi.EmptyAddr)
	t.Log(time)
	time = Drop.waitTime(netapi.EmptyAddr)
	t.Log(time)
	time = Drop.waitTime(netapi.EmptyAddr)
	t.Log(time)
	time = Drop.waitTime(netapi.EmptyAddr)
	t.Log(time)
}
