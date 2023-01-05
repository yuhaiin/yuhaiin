package simplehttp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"

	tps "github.com/Asutorufa/yuhaiin/internal/http/templates"
	"github.com/Asutorufa/yuhaiin/internal/shunt"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	snode "github.com/Asutorufa/yuhaiin/pkg/protos/node/grpc"
	"golang.org/x/exp/maps"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type groupHandler struct {
	emptyHTTP
	nm snode.NodeServer
}

func (g *groupHandler) Get(w http.ResponseWriter, r *http.Request) error {
	group := r.URL.Query().Get("name")
	ns, err := g.nm.Manager(context.TODO(), &wrapperspb.StringValue{})
	if err != nil {
		return err
	}
	if group == "" {
		return g.groupList(w, r, ns)
	} else {
		return g.group(w, r, ns, group)
	}
}

func (g *groupHandler) groupList(w http.ResponseWriter, r *http.Request, ns *node.Manager) error {
	groups := maps.Keys(ns.GroupsV2)
	sort.Strings(groups)
	return TPS.BodyExecute(w, groups, tps.GROUP_LIST)
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

type tag struct {
	emptyHTTP
	nm snode.NodeServer
	ts snode.TagServer
	st *shunt.Shunt
}

func (t *tag) Get(w http.ResponseWriter, r *http.Request) error {
	m, err := t.nm.Manager(context.TODO(), &wrapperspb.StringValue{})
	if err != nil {
		return err
	}

	tags := make(map[string]string)

	for k, v := range m.Tags {
		tags[k] = v.GetHash()[0]
	}

	for _, v := range t.st.Tags() {
		if _, ok := tags[v]; !ok {
			tags[v] = ""
		}
	}

	groups := make(map[string]map[string]string)

	for k, v := range m.GroupsV2 {
		groups[k] = v.NodesV2
	}

	gs, _ := json.Marshal(groups)

	return TPS.BodyExecute(w, map[string]any{
		"Tags":      tags,
		"GroupJSON": string(gs),
	}, tps.TAG)
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

	_, err = t.ts.Save(context.TODO(), &snode.SaveTagReq{
		Tag:  z["tag"],
		Hash: z["hash"],
	})
	return err
}

func (t *tag) Delete(w http.ResponseWriter, r *http.Request) error {
	tag := r.URL.Query().Get("tag")

	_, err := t.ts.Remove(context.TODO(), &wrapperspb.StringValue{
		Value: tag,
	})
	return err
}
