package node

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"testing"
	"time"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/fixed"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
	"golang.org/x/net/nettest"
)

func TestSet(t *testing.T) {
	lis, err := nettest.NewLocalListener("tcp")
	assert.NoError(t, err)
	defer lis.Close()

	host, port, err := net.SplitHostPort(lis.Addr().String())
	assert.NoError(t, err)
	portInt, err := strconv.Atoi(port)
	assert.NoError(t, err)

	fmt.Println(host, portInt)

	runtime := newTestRuntime(t)
	p1 := testNode(t, "a", "feefe")
	fixed, err := contractnode.NewTypedProtocol(contractnode.Fixed{
		Host: host,
		Port: int32(portInt),
	})
	assert.NoError(t, err)
	p2 := contractnode.Node{
		ID:      "b",
		Name:    "fafaf",
		Group:   "group",
		Origin:  "manual",
		Enabled: true,
		Chain:   []contractnode.Protocol{fixed},
	}
	_, err = runtime.Save(context.Background(), p1)
	assert.NoError(t, err)
	_, err = runtime.Save(context.Background(), p2)
	assert.NoError(t, err)

	se, err := NewContractSet([]string{"a", "b"}, "round_robin", runtime)
	assert.NoError(t, err)

	c, err := netapi.ParseAddress("tcp", "www.example.com")
	assert.NoError(t, err)

	ctx, cancel := context.WithTimeout(t.Context(), time.Second*10)
	defer cancel()

	conn, err := se.Conn(ctx, c)
	assert.NoError(t, err)
	defer conn.Close()
}
