package simplehttp

import (
	"context"
	"fmt"
	"net/http"
	"sort"

	"github.com/Asutorufa/yuhaiin/pkg/net/utils"
	grpcnode "github.com/Asutorufa/yuhaiin/pkg/protos/grpc/node"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type groupHandler struct {
	emptyHTTP
	nm grpcnode.NodeManagerServer
}

func (g *groupHandler) Get(w http.ResponseWriter, r *http.Request) {
	group := r.URL.Query().Get("name")
	if group == "" {
		g.groupList(w, r)
	} else {
		g.group(w, group)
	}
}

func (g *groupHandler) groupList(w http.ResponseWriter, r *http.Request) {
	ns, err := g.nm.GetManager(context.TODO(), &wrapperspb.StringValue{})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
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

func (g *groupHandler) group(w http.ResponseWriter, group string) {
	ns, err := g.nm.GetManager(context.TODO(), &wrapperspb.StringValue{})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	nhm := ns.GroupNodesMap[group].NodeHashMap
	nds := ns.GroupNodesMap[group].Nodes
	sort.Strings(nds)

	str := utils.GetBuffer()
	defer utils.PutBuffer(str)

	str.WriteString(fmt.Sprintf(`<script>%s</script>`, nodeJS))

	for _, n := range nds {
		str.WriteString(fmt.Sprintf(`<div id="%s">`, "i"+nhm[n]))
		str.WriteString(fmt.Sprintf(`<input type="radio" name="select_node" value="%s">`, nhm[n]))
		str.WriteString(fmt.Sprintf(`<a href='javascript: nodeSelectOrDetail("%s")'>%s</a>`, nhm[n], n))
		str.WriteString("&nbsp;&nbsp;")
		str.WriteString(`TCP: <a class="tcp">N/A</a>`)
		str.WriteString("&nbsp;&nbsp;")
		str.WriteString(`UDP: <a class="udp">N/A</a>`)
		str.WriteString("&nbsp;&nbsp;")
		str.WriteString(fmt.Sprintf(`<a class="test" href='javascript:latency("%s")'>Test</a>`, nhm[n]))
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
