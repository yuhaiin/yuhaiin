package node

import (
	"context"
	"errors"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestSet(t *testing.T) {
	GetDialerByID = func(ctx context.Context, hash string) (netapi.Proxy, error) {
		return netapi.NewErrProxy(errors.New("test")), nil
	}

	se, err := NewSet(protocol.Set_builder{
		Nodes: []string{"aaaa"},
	}.Build(), nil)
	assert.NoError(t, err)

	t.Log(se.Conn(context.TODO(), netapi.EmptyAddr))
}
