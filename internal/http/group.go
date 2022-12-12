package simplehttp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"

	tps "github.com/Asutorufa/yuhaiin/internal/http/templates"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	snode "github.com/Asutorufa/yuhaiin/pkg/protos/node/grpc"
	"google.golang.org/protobuf/encoding/protojson"
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
	sort.Strings(ns.Groups)
	return TPS.BodyExecute(w, ns.GetGroups(), tps.GROUP_LIST)
}

func (g *groupHandler) group(w http.ResponseWriter, r *http.Request, ns *node.Manager, group string) error {
	z, ok := ns.GroupNodesMap[group]
	if !ok {
		return fmt.Errorf("can't find %s", group)
	}

	sort.Strings(z.Nodes)
	data, err := protojson.Marshal(z)
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

	groups := make(map[string]map[string]string)

	for k, v := range m.GroupNodesMap {
		groups[k] = v.NodeHashMap
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
