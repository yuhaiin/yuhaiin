package node

import (
	"context"
	"encoding/json"
	"log"
	"reflect"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestNodeManager(t *testing.T) {
	n, err := NewNodeManager("/tmp/yuhaiin/nodeManagerTest/config.json")
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	_, err = n.SaveLinks(context.TODO(),
		&node.SaveLinkReq{
			Links: []*node.NodeLink{
				{
					Name: "test",
					Type: node.NodeLink_reserve,
					Url:  "test",
				},
			},
		},
	)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	// _, err = n.RefreshSubscr(context.TODO(), &emptypb.Empty{})
	// if err != nil {
	// t.Error(err)
	// t.FailNow()
	// }
	hash := "db084f1d4f90140540e47a13ca77204d1f597e933481d58dfe2e5860f76f75ff"
	t.Log(n.GetNode(context.TODO(), &wrapperspb.StringValue{Value: hash}))
	t.Log(n.Latency(context.TODO(), &node.LatencyReq{NodeHash: []string{hash}}))
	// t.Log(n.node)
}

func TestDelete(t *testing.T) {
	a := []string{"a", "b", "c"}

	for i := range a {
		if a[i] != "b" {
			continue
		}

		log.Println(i, a[:i], a[i:])
		a = append(a[:i], a[i+1:]...)
		break
	}

	t.Log(a)
}

func TestMarshalMap(t *testing.T) {
	s := &node.Point{
		Hash:   "n_hash",
		Name:   "n_name",
		Group:  "n_group",
		Origin: node.Point_manual,
	}

	data, _ := protojson.MarshalOptions{UseProtoNames: true, EmitUnpopulated: true}.Marshal(s)

	var z map[string]interface{}

	err := json.Unmarshal(data, &z)
	if err != nil {
		t.Error(err)
	}

	t.Log(z)

	for k, v := range z {
		t.Log(k)
		switch x := v.(type) {
		case string:
			t.Log("string", x)
		case map[string]interface{}:
			t.Log("map[string]interface{}", x)
			x["server"] = "server2"
		}
	}

	b, err := json.Marshal(z)
	if err != nil {
		t.Error(err)
	}

	t.Log(string(b))

	err = protojson.Unmarshal(b, s)
	if err != nil {
		t.Error(err)
	}

	t.Log(s)
}

func TestProtoMsgType(t *testing.T) {
	p := &node.PointProtocol{
		Protocol: &node.PointProtocol_None{},
	}

	t.Log(reflect.TypeOf(p.GetProtocol()) == reflect.TypeOf(&node.PointProtocol_None{}))
}
