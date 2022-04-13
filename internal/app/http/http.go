package simplehttp

import (
	"context"
	_ "embed"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/Asutorufa/yuhaiin/internal/app"
	"github.com/Asutorufa/yuhaiin/internal/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	"github.com/Asutorufa/yuhaiin/pkg/subscr"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

//go:embed click.js
var JS []byte

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

		str := strings.Builder{}

		for _, n := range ns.GetGroups() {
			str.WriteString(fmt.Sprintf(`<a href="/nodes?group=%s">%s</a>`, n, n))
			str.WriteString("<br/>")
			str.WriteByte('\n')
		}

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

		str.WriteString(fmt.Sprintf(`<script>%s</script>`, JS))
		for _, v := range nds {
			str.WriteString("<p>")
			str.WriteString(fmt.Sprintf(`<a href="/node?hash=%s">%s</a>`, nhm[v], v))
			str.WriteString("&nbsp;&nbsp;")
			str.WriteString(fmt.Sprintf(`<a id=%s>0.00ms</a>`, nhm[v]))
			str.WriteString("&nbsp;&nbsp;")
			str.WriteString(fmt.Sprintf(`<a href='javascript:latency("%s","%s")'>Test</a>`, nhm[v], nhm[v]))
			str.WriteString("&nbsp;&nbsp;")
			str.WriteString(fmt.Sprintf(`<a href='/use?hash=%s'>Use This</a>`, nhm[v]))
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

		w.Write([]byte(createHTML(fmt.Sprintf(`<pre>%s</pre>`, string(data)))))
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
			str.WriteString(fmt.Sprintf(`<a>%d| %s, %s <-> %s</a>`, c.GetId(), c.GetAddr(), c.GetLocal(), c.GetRemote()))
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

		data, err := protojson.MarshalOptions{Indent: "  "}.Marshal(c)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Write([]byte(createHTML(fmt.Sprintf(`<pre>%s</pre>`, string(data)))))
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
				<a href="/conn/list">CONNECTIONS</a>
				<a href="/config">CONFIG</a>
				<a href="/debug/pprof">PPROF</a>
			</p>
		</body>
	</html>
	`, s)
}
