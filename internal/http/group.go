package simplehttp

import (
	"context"
	"net/http"
	"sort"

	tps "github.com/Asutorufa/yuhaiin/internal/http/templates"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	snode "github.com/Asutorufa/yuhaiin/pkg/protos/node/grpc"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type groupHandler struct {
	emptyHTTP
	nm snode.NodeManagerServer
}

func (g *groupHandler) Get(w http.ResponseWriter, r *http.Request) error {
	group := r.URL.Query().Get("name")
	ns, err := g.nm.GetManager(context.TODO(), &wrapperspb.StringValue{})
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
		return g.groupList(w, r, ns)
	}
	sort.Strings(z.Nodes)

	return TPS.Execute(w, z, tps.GROUP)
}
