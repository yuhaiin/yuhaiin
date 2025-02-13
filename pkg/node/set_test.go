package node

import (
	"context"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestSet(t *testing.T) {
	se, err := NewSet(protocol.Set_builder{
		Nodes: []string{"aaaa"},
	}.Build(), newTestManager())
	assert.NoError(t, err)

	t.Log(se.Conn(context.TODO(), netapi.EmptyAddr))
}
