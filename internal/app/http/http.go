package simplehttp

import (
	"context"
	_ "embed"
	"fmt"
	"io/ioutil"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/Asutorufa/yuhaiin/internal/app"
	"github.com/Asutorufa/yuhaiin/internal/config"
	protoconfig "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	"github.com/Asutorufa/yuhaiin/pkg/subscr"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

//go:embed node.js
var nodeJS []byte

//go:embed config.js
var configJS []byte

//go:embed sub.js
var subJS []byte

//go:embed toast.html
var toastHTML []byte

func Httpserver(nodeManager *subscr.NodeManager, connManager *app.ConnManager, conf *config.Config) {
	http.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte{}) })

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		point, err := nodeManager.Now(context.TODO(), &emptypb.Empty{})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		data, err := protojson.MarshalOptions{Indent: "  "}.Marshal(point)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Write([]byte(createHTML(fmt.Sprintf(`<pre>%s</pre>`, string(data)))))
	})

	http.HandleFunc("/group", func(w http.ResponseWriter, r *http.Request) {
		ns, err := nodeManager.GetManager(context.TODO(), &wrapperspb.StringValue{})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		sort.Strings(ns.Groups)

		str := strings.Builder{}

		for _, n := range ns.GetGroups() {
			str.WriteString(fmt.Sprintf(`<a href="/nodes?group=%s">%s</a>`, n, n))
			str.WriteString("<br/>")
			str.WriteByte('\n')
		}

		str.WriteString("<hr/>")
		str.WriteString(`<a href="/node/add">Add New Node</a>`)

		w.Write([]byte(createHTML(str.String())))
	})

	http.HandleFunc("/nodes", func(w http.ResponseWriter, r *http.Request) {
		group := r.URL.Query().Get("group")

		ns, err := nodeManager.GetManager(context.TODO(), &wrapperspb.StringValue{})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		nhm := ns.GroupNodesMap[group].NodeHashMap
		nds := ns.GroupNodesMap[group].Nodes
		sort.Strings(nds)

		str := strings.Builder{}

		str.WriteString(fmt.Sprintf(`<script>%s</script>`, nodeJS))
		for _, v := range nds {
			str.WriteString("<p>")
			str.WriteString(fmt.Sprintf(`<a href="/node?hash=%s">%s</a>`, nhm[v], v))
			str.WriteString("&nbsp;&nbsp;")
			str.WriteString(fmt.Sprintf(`<a id=%s>0.00ms</a>`, nhm[v]))
			str.WriteString("&nbsp;&nbsp;")
			str.WriteString(fmt.Sprintf(`<a href='javascript:latency("%s","%s")'>Test</a>`, nhm[v], nhm[v]))
			str.WriteString("&nbsp;&nbsp;")
			str.WriteString(fmt.Sprintf(`<a href='/use?hash=%s'>Use This</a>`, nhm[v]))
			str.WriteString("&nbsp;&nbsp;")
			str.WriteString(fmt.Sprintf(`<a href='javascript: del("%s");'>Delete</a>`, nhm[v]))
			str.WriteString("</p>")
		}
		w.Write([]byte(createHTML(str.String())))
	})

	http.HandleFunc("/node", func(w http.ResponseWriter, r *http.Request) {
		hash := r.URL.Query().Get("hash")

		n, err := nodeManager.GetNode(context.TODO(), &wrapperspb.StringValue{Value: hash})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		data, err := protojson.MarshalOptions{Indent: "  "}.Marshal(n)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		str := strings.Builder{}
		str.WriteString("<script>")
		str.Write(configJS)
		str.WriteString("</script>")
		str.WriteString(fmt.Sprintf(`<pre id="node" contenteditable="false">%s</pre>`, string(data)))
		str.WriteString("<p>")
		str.WriteString(`<a href='javascript: document.getElementById("node").setAttribute("contenteditable", "true"); '>Edit</a>`)
		str.WriteString("&nbsp;&nbsp;")
		str.WriteString(`<a href='javascript: save("node","/node/save");'>Save</a>`)
		str.WriteString("</p>")
		str.WriteString(`<pre id="error"></pre>`)

		w.Write([]byte(createHTML(str.String())))
	})

	http.HandleFunc("/node/add", func(w http.ResponseWriter, r *http.Request) {
		str := strings.Builder{}
		str.WriteString("<script>")
		str.Write(configJS)
		str.WriteString("</script>")

		data, _ := protojson.MarshalOptions{Indent: "  ", EmitUnpopulated: true}.Marshal(&node.Point{
			Name:   "xxx",
			Group:  "xxx",
			Origin: node.Point_manual,
			Protocols: []*node.PointProtocol{
				{
					Protocol: &node.PointProtocol_Simple{
						Simple: &node.Simple{
							Tls: &node.TlsConfig{},
						},
					},
				},
				{
					Protocol: &node.PointProtocol_None{},
				},
			},
		})
		str.WriteString(`<pre contenteditable="true" id="node">`)
		str.Write(data)
		str.WriteString("</pre>")
		str.WriteString(`<a href='javascript: save("node","/node/save");'>Save</a>`)
		str.WriteString("&nbsp;&nbsp;&nbsp;&nbsp;")
		str.WriteString(`<a href="/node/template">Protocols Template</a>`)

		w.Write([]byte(createHTML(str.String())))
	})

	http.HandleFunc("/node/save", func(w http.ResponseWriter, r *http.Request) {
		data, err := ioutil.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		point := &node.Point{}
		err = protojson.UnmarshalOptions{DiscardUnknown: true}.Unmarshal(data, point)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		_, err = nodeManager.SaveNode(context.TODO(), point)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Write([]byte("successful"))
	})

	http.HandleFunc("/node/delete", func(w http.ResponseWriter, r *http.Request) {
		hash := r.URL.Query().Get("hash")
		if hash == "" {
			http.Error(w, "hash is empty", http.StatusInternalServerError)
			return
		}

		_, err := nodeManager.DeleteNode(context.TODO(), &wrapperspb.StringValue{Value: hash})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Write(nil)
	})

	http.HandleFunc("/node/template", func(w http.ResponseWriter, r *http.Request) {
		create := func(name string, data proto.Message) string {
			b, _ := protojson.MarshalOptions{Indent: "  ", EmitUnpopulated: true}.Marshal(data)
			str := strings.Builder{}
			str.WriteString("<hr/>")
			str.WriteString(name)
			str.WriteString("<pre>")
			str.Write(b)
			str.WriteString("</pre>")

			return str.String()
		}

		str := strings.Builder{}
		str.WriteString("TEMPLATE")
		str.WriteString(create("simple", &node.PointProtocol{Protocol: &node.PointProtocol_Simple{Simple: &node.Simple{Tls: &node.TlsConfig{CaCert: [][]byte{{0x0, 0x01}}}}}}))
		str.WriteString(create("none", &node.PointProtocol{Protocol: &node.PointProtocol_None{}}))
		str.WriteString(create("websocket", &node.PointProtocol{Protocol: &node.PointProtocol_Websocket{Websocket: &node.Websocket{Tls: &node.TlsConfig{CaCert: [][]byte{{0x0, 0x01}}}}}}))
		str.WriteString(create("quic", &node.PointProtocol{Protocol: &node.PointProtocol_Quic{Quic: &node.Quic{Tls: &node.TlsConfig{CaCert: [][]byte{{0x0, 0x01}}}}}}))
		str.WriteString(create("shadowsocks", &node.PointProtocol{Protocol: &node.PointProtocol_Shadowsocks{}}))
		str.WriteString(create("obfshttp", &node.PointProtocol{Protocol: &node.PointProtocol_ObfsHttp{}}))
		str.WriteString(create("shadowsocksr", &node.PointProtocol{Protocol: &node.PointProtocol_Shadowsocksr{}}))
		str.WriteString(create("vmess", &node.PointProtocol{Protocol: &node.PointProtocol_Vmess{}}))
		str.WriteString(create("trojan", &node.PointProtocol{Protocol: &node.PointProtocol_Trojan{}}))

		w.Write([]byte(createHTML(str.String())))
	})

	http.HandleFunc("/latency", func(w http.ResponseWriter, r *http.Request) {
		hash := r.URL.Query().Get("hash")
		lt, err := nodeManager.Latency(context.TODO(), &node.LatencyReq{NodeHash: []string{hash}})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if _, ok := lt.HashLatencyMap[hash]; !ok {
			http.Error(w, "test latency timeout or can't connect", http.StatusInternalServerError)
			return
		}

		w.Write([]byte(lt.HashLatencyMap[hash]))
	})

	http.HandleFunc("/use", func(w http.ResponseWriter, r *http.Request) {
		hash := r.URL.Query().Get("hash")

		p, err := nodeManager.Use(context.TODO(), &wrapperspb.StringValue{Value: hash})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		data, err := protojson.MarshalOptions{Indent: "  "}.Marshal(p)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Write([]byte(createHTML(fmt.Sprintf(`<pre>%s</pre>`, string(data)))))
	})

	http.HandleFunc("/conn/list", func(w http.ResponseWriter, r *http.Request) {
		conns, err := connManager.Conns(context.TODO(), &emptypb.Empty{})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		sort.Slice(conns.Connections, func(i, j int) bool { return conns.Connections[i].Id < conns.Connections[j].Id })

		str := strings.Builder{}

		for _, c := range conns.GetConnections() {
			str.WriteString("<p>")
			str.WriteString(fmt.Sprintf(`<a>%d| [%s] %s, %s <-> %s</a>`, c.GetId(), c.GetMark(), c.GetAddr(), c.GetLocal(), c.GetRemote()))
			str.WriteString("&nbsp;&nbsp;")
			str.WriteString(fmt.Sprintf(`<a href='/conn/close?id=%d'>Close</a>`, c.GetId()))
			str.WriteString("</p>")
		}

		w.Write([]byte(createHTML(str.String())))
	})

	http.HandleFunc("/conn/close", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")

		i, err := strconv.Atoi(id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		_, err = connManager.CloseConn(context.TODO(), &statistic.CloseConnsReq{Conns: []int64{int64(i)}})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/conn/list", http.StatusFound)
	})

	http.HandleFunc("/config", func(w http.ResponseWriter, r *http.Request) {
		c, err := conf.Load(context.TODO(), &emptypb.Empty{})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		data, err := protojson.MarshalOptions{Indent: "  ", EmitUnpopulated: true}.Marshal(c)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		str := strings.Builder{}
		str.WriteString("<script>")
		str.Write(configJS)
		str.WriteString("</script>")
		str.WriteString(fmt.Sprintf(`<pre id="config" contenteditable="false">%s</pre>`, string(data)))
		str.WriteString("<p>")
		str.WriteString(`<a href='javascript: document.getElementById("config").setAttribute("contenteditable", "true"); '>Edit</a>`)
		str.WriteString("&nbsp;&nbsp;")
		str.WriteString(`<a href='javascript: save("config","/config/save");'>Save</a>`)
		str.WriteString("</p>")
		str.WriteString(`<pre id="error"></pre>`)
		w.Write([]byte(createHTML(str.String())))
	})

	http.HandleFunc("/config/save", func(w http.ResponseWriter, r *http.Request) {
		data, err := ioutil.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		config := &protoconfig.Setting{}
		err = protojson.UnmarshalOptions{DiscardUnknown: true}.Unmarshal(data, config)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		_, err = conf.Save(context.TODO(), config)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Write([]byte("successful"))
	})

	http.HandleFunc("/sub", func(w http.ResponseWriter, r *http.Request) {
		links, err := nodeManager.GetLinks(context.TODO(), &emptypb.Empty{})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		str := strings.Builder{}
		str.Write(toastHTML)
		str.WriteString("<script>")
		str.Write(subJS)
		str.WriteString("</script>")
		ls := make([]string, 0, len(links.Links))
		for v := range links.Links {
			ls = append(ls, v)
		}
		sort.Strings(ls)

		for _, v := range ls {
			l := links.Links[v]
			str.WriteString("<p>")
			str.WriteString(fmt.Sprintf(`<a href='javascript: copy("%s");'>%s</a>`, l.GetUrl(), l.GetName()))
			str.WriteString("&nbsp;&nbsp;")
			str.WriteString(fmt.Sprintf(`<a href='/sub/delete?name=%s'>Delete</a>`, l.GetName()))
			str.WriteString("&nbsp;&nbsp;")
			str.WriteString(fmt.Sprintf(`<a href='/sub/update?name=%s'>Update</a>`, l.GetName()))
			str.WriteString("</p>")
		}

		str.WriteString("<hr/>")
		str.WriteString("Add a New Link")
		str.WriteString("<p>")
		str.WriteString(`<a>Name:</a>`)
		str.WriteString("&nbsp;&nbsp;")
		str.WriteString(`<input type="text" id="name" value="">`)
		str.WriteString("&nbsp;&nbsp;")
		str.WriteString(`<a>Link:</a>`)
		str.WriteString("&nbsp;&nbsp;")
		str.WriteString(`<input type="text" id="link" value="">`)
		str.WriteString("&nbsp;&nbsp;")
		str.WriteString(`<a href="javascript: add();">ADD</a>`)
		str.WriteString("</p>")
		w.Write([]byte(createHTML(str.String())))
	})

	http.HandleFunc("/sub/add", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		link := r.URL.Query().Get("link")

		if name == "" || link == "" {
			http.Error(w, "name or link is empty", http.StatusInternalServerError)
			return
		}

		_, err := nodeManager.SaveLinks(context.TODO(), &node.SaveLinkReq{
			Links: []*node.NodeLink{
				{
					Name: name,
					Url:  link,
				},
			},
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/sub", http.StatusFound)
	})

	http.HandleFunc("/sub/delete", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		if name == "" {
			http.Redirect(w, r, "/sub", http.StatusFound)
			return
		}

		_, err := nodeManager.DeleteLinks(context.TODO(), &node.LinkReq{Names: []string{name}})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/sub", http.StatusFound)
	})

	http.HandleFunc("/sub/update", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		if name == "" {
			http.Redirect(w, r, "/sub", http.StatusFound)
			return
		}

		_, err := nodeManager.UpdateLinks(context.TODO(), &node.LinkReq{Names: []string{name}})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/sub", http.StatusFound)
	})
}

func createHTML(s string) string {
	return fmt.Sprintf(`
	<!DOCTYPE html>
	<html>
		<head>
			<meta charset="UTF-8">
			<title>yuhaiin</title>
			<style>
				p {line-height:50%%;}
			</style>
		</head>
		<body>
			%s
			<hr/>
			<p>
				<a href="/">HOME</a>
				<a href="/group">GROUP</a>
				<a href="/sub">SUBSCRIBE</a>
				<a href="/conn/list">CONNECTIONS</a>
				<a href="/config">CONFIG</a>
				<a href="/debug/pprof">PPROF</a>
			</p>
		</body>
	</html>
	`, s)
}
