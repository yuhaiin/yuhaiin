package node

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	_ "github.com/Asutorufa/yuhaiin/pkg/net/proxy/fixed"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/point"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
	"golang.org/x/net/nettest"
	"google.golang.org/protobuf/proto"
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

	mg := newTestManager()
	p1 := point.Point_builder{
		Hash:  proto.String("a"),
		Name:  proto.String("feefe"),
		Group: proto.String("group"),
	}.Build()
	p2 := point.Point_builder{
		Hash:  proto.String("b"),
		Name:  proto.String("fafaf"),
		Group: proto.String("group"),
		Protocols: []*protocol.Protocol{
			protocol.Protocol_builder{
				Simple: protocol.Simple_builder{
					Host: proto.String(host),
					Port: proto.Int32(int32(portInt)),
				}.Build(),
			}.Build(),
		},
	}.Build()
	mg.SaveNode(p1, p2)

	se, err := NewSet(protocol.Set_builder{
		Strategy: protocol.Set_round_robin.Enum(),
		Nodes:    []string{"a", "b"},
	}.Build(), mg)
	assert.NoError(t, err)

	c, err := netapi.ParseAddress("tcp", "www.example.com")
	assert.NoError(t, err)

	ctx, cancel := context.WithTimeout(t.Context(), time.Second*10)
	defer cancel()

	conn, err := se.Conn(ctx, c)
	assert.NoError(t, err)
	defer conn.Close()
}
