package subscr

import (
	"context"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestMarshalJson(t *testing.T) {
	s := &Point{
		NHash:   "n_hash",
		NName:   "n_name",
		NGroup:  "n_group",
		NOrigin: Point_manual,
		Node: &Point_Shadowsocksr{
			Shadowsocksr: &Shadowsocksr{
				Server: "server",
			},
		},
	}

	ss, err := protojson.Marshal(s)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	t.Log(string(ss))
	zz := &Point{}
	err = protojson.Unmarshal(ss, zz)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	t.Log(zz)

	s.Node = &Point_Vmess{
		Vmess: &Vmess{
			Address: "address",
		},
	}

	ss, err = protojson.Marshal(s)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	t.Log(string(ss))
	err = protojson.Unmarshal(ss, zz)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	t.Log(zz)
}

func TestNodeManager(t *testing.T) {
	n, err := NewNodeManager("/tmp/yuhaiin/nodeManagerTest/config.json")
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	_, err = n.AddLink(context.TODO(), &NodeLink{
		Name: "test",
		Type: "test",
		Url:  "test",
	})
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
	t.Log(n.Latency(context.TODO(), &wrapperspb.StringValue{Value: hash}))
	// t.Log(n.node)
}
