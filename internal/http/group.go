package simplehttp

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"

	"github.com/Asutorufa/yuhaiin/pkg/components/shunt"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	snode "github.com/Asutorufa/yuhaiin/pkg/protos/node/grpc"
	pt "github.com/Asutorufa/yuhaiin/pkg/protos/node/tag"
	"golang.org/x/exp/maps"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type groupHandler struct {
	nm snode.NodeServer
}

func (g *groupHandler) Get(w http.ResponseWriter, r *http.Request) error {
	group := r.URL.Query().Get("name")
	ns, err := g.nm.Manager(r.Context(), &wrapperspb.StringValue{})
	if err != nil {
		return err
	}

	return g.group(w, r, ns, group)
}

func (g *groupHandler) group(w http.ResponseWriter, r *http.Request, ns *node.Manager, group string) error {
	z, ok := ns.GroupsV2[group]
	if !ok {
		return fmt.Errorf("can't find %s", group)
	}
	data, err := json.Marshal(z.NodesV2)
	if err != nil {
		return err
	}

	w.Write(data)
	return nil
}

func (g *groupHandler) GroupList(w http.ResponseWriter, r *http.Request) error {
	ns, err := g.nm.Manager(r.Context(), &wrapperspb.StringValue{})
	if err != nil {
		return err
	}
	groups := maps.Keys(ns.GroupsV2)
	sort.Strings(groups)

	data, err := json.Marshal(groups)
	if err != nil {
		return err
	}

	w.Write(data)
	return nil
}

type tag struct {
	nm snode.NodeServer
	ts snode.TagServer
	st *shunt.Shunt
}

func (t *tag) List(w http.ResponseWriter, r *http.Request) error {
	m, err := t.nm.Manager(r.Context(), &wrapperspb.StringValue{})
	if err != nil {
		return err
	}

	type tag struct {
		Hash string `json:"hash"`
		Type string `json:"type"`
	}

	tags := make(map[string]tag)

	for k, v := range m.Tags {
		tags[k] = tag{
			Hash: v.GetHash()[0],
			Type: v.Type.String(),
		}
	}

	for _, v := range t.st.Tags() {
		if _, ok := tags[v]; !ok {
			tags[v] = tag{}
		}
	}

	groups := make(map[string]map[string]string)

	for k, v := range m.GroupsV2 {
		groups[k] = v.NodesV2
	}

	gs, err := json.Marshal(map[string]any{
		"tags":   tags,
		"groups": groups,
	})
	if err != nil {
		return err
	}

	_, err = w.Write(gs)
	return err
}

func (t *tag) Post(w http.ResponseWriter, r *http.Request) error {
	data, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}

	z := make(map[string]string)

	if err = json.Unmarshal(data, &z); err != nil {
		return err
	}

	tYPE, ok := pt.Type_value[z["type"]]
	if !ok {
		return fmt.Errorf("unknown tag type: %v", z["type"])
	}

	_, err = t.ts.Save(r.Context(), &snode.SaveTagReq{
		Tag:  z["tag"],
		Hash: z["hash"],
		Type: pt.Type(tYPE),
	})
	return err
}

func (t *tag) Delete(w http.ResponseWriter, r *http.Request) error {
	tag := r.URL.Query().Get("tag")

	_, err := t.ts.Remove(r.Context(), &wrapperspb.StringValue{
		Value: tag,
	})
	return err
}
