package subscr

import (
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
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
