package simplehttp

import (
	"context"
	"fmt"
	"net/http"
	"sort"

	"github.com/Asutorufa/yuhaiin/pkg/net/utils"
	grpcnode "github.com/Asutorufa/yuhaiin/pkg/protos/grpc/node"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type groupHandler struct {
	emptyHTTP
	nm grpcnode.NodeManagerServer
}

func (g *groupHandler) Get(w http.ResponseWriter, r *http.Request) {
	group := r.URL.Query().Get("name")
	ns, err := g.nm.GetManager(context.TODO(), &wrapperspb.StringValue{})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if group == "" {
		g.groupList(w, r, ns)
	} else {
		g.group(w, r, ns, group)
	}
}

func (g *groupHandler) groupList(w http.ResponseWriter, r *http.Request, ns *node.Manager) {
	sort.Strings(ns.Groups)

	str := utils.GetBuffer()
	defer utils.PutBuffer(str)

	for _, n := range ns.GetGroups() {
		str.WriteString(fmt.Sprintf(`<a href="/group?name=%s">%s</a>`, n, n))
		str.WriteString("<br/>")
		str.WriteByte('\n')
	}

	str.WriteString("<hr/>")
	str.WriteString(`<a href="/node?page=new_node">Add New Node</a>`)

	w.Write([]byte(createHTML(str.String())))
}

func (g *groupHandler) group(w http.ResponseWriter, r *http.Request, ns *node.Manager, group string) {
	z, ok := ns.GroupNodesMap[group]
	if !ok {
		g.groupList(w, r, ns)
		return
	}
	sort.Strings(z.Nodes)

	str := utils.GetBuffer()
	defer utils.PutBuffer(str)

	str.WriteString(fmt.Sprintf(`<script>%s</script>`, nodeJS))

	for _, n := range z.Nodes {
		str.WriteString(fmt.Sprintf(`<div id="%s">`, "i"+z.NodeHashMap[n]))
		str.WriteString(fmt.Sprintf(`<input type="radio" name="select_node" value="%s">`, z.NodeHashMap[n]))
		str.WriteString(fmt.Sprintf(`<a href='javascript: nodeSelectOrDetail("%s")'>%s</a>`, z.NodeHashMap[n], n))
		str.WriteString("&nbsp;&nbsp;")
		str.WriteString(`TCP: <a class="tcp">N/A</a>`)
		str.WriteString("&nbsp;&nbsp;")
		str.WriteString(`UDP: <a class="udp">N/A</a>`)
		str.WriteString("&nbsp;&nbsp;")
		str.WriteString(fmt.Sprintf(`<a class="test" href='javascript:latency("%s")'>Test</a>`, z.NodeHashMap[n]))
		str.WriteString("</div>")
	}
	str.WriteString("<br/>")
	str.WriteString("<a href='javascript: use(\"tcpudp\");'>USE</a>")
	str.WriteString("&nbsp;&nbsp;")
	str.WriteString("<a href='javascript: use(\"tcp\");'>USE FOR TCP</a>")
	str.WriteString("&nbsp;&nbsp;")
	str.WriteString("<a href='javascript: use(\"udp\");'>USE FOR UDP</a>")
	str.WriteString("&nbsp;&nbsp;")
	str.WriteString("<a href='javascript: del();'>DELETE</a>")
	w.Write([]byte(createHTML(str.String())))
}
