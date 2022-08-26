package simplehttp

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/Asutorufa/yuhaiin/pkg/net/utils"
	grpcnode "github.com/Asutorufa/yuhaiin/pkg/protos/grpc/node"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type nodeHandler struct {
	emptyHTTP
	nm grpcnode.NodeManagerServer
}

func (nn *nodeHandler) Get(w http.ResponseWriter, r *http.Request) {
	page := r.URL.Query().Get("page")
	if page == "new_node" {
		str := utils.GetBuffer()
		defer utils.PutBuffer(str)

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
		str.WriteString(`<a href='javascript: save("node","/node");'>Save</a>`)
		str.WriteString("&nbsp;&nbsp;&nbsp;&nbsp;")
		str.WriteString(`<a href="/node?page=template">Protocols Template</a>`)

		w.Write([]byte(createHTML(str.String())))
		return
	}

	if page == "template" {
		create := func(name string, data proto.Message) string {
			b, _ := protojson.MarshalOptions{Indent: "  ", EmitUnpopulated: true}.Marshal(data)
			str := utils.GetBuffer()
			defer utils.PutBuffer(str)

			str.WriteString("<hr/>")
			str.WriteString(name)
			str.WriteString("<pre>")
			str.Write(b)
			str.WriteString("</pre>")

			return str.String()
		}

		str := utils.GetBuffer()
		defer utils.PutBuffer(str)

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
		str.WriteString(create("socks5", &node.PointProtocol{Protocol: &node.PointProtocol_Socks5{}}))
		str.WriteString(create("http", &node.PointProtocol{Protocol: &node.PointProtocol_Http{}}))

		w.Write([]byte(createHTML(str.String())))
		return
	}

	hash := r.URL.Query().Get("hash")

	n, err := nn.nm.GetNode(context.TODO(), &wrapperspb.StringValue{Value: hash})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	data, err := protojson.MarshalOptions{Indent: "  ", EmitUnpopulated: true}.Marshal(n)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	str := utils.GetBuffer()
	defer utils.PutBuffer(str)

	str.WriteString("<script>")
	str.Write(configJS)
	str.Write(nodeJS)
	str.WriteString("</script>")
	str.WriteString(fmt.Sprintf(`<pre id="node" contenteditable="false">%s</pre>`, string(data)))
	str.WriteString("<p>")
	str.WriteString("<a href='javascript: useByHash(\"tcpudp\",\"" + n.Hash + "\");'>USE</a>")
	str.WriteString("&nbsp;&nbsp;")
	str.WriteString("<a href='javascript: useByHash(\"tcp\",\"" + n.Hash + "\");'>USE FOR TCP</a>")
	str.WriteString("&nbsp;&nbsp;")
	str.WriteString("<a href='javascript: useByHash(\"udp\",\"" + n.Hash + "\");'>USE FOR UDP</a>")
	str.WriteString("&nbsp;&nbsp;")
	str.WriteString(`<a href='javascript: document.getElementById("node").setAttribute("contenteditable", "true"); '>Edit</a>`)
	str.WriteString("&nbsp;&nbsp;")
	str.WriteString(`<a href='javascript: save("node","/node");'>Save</a>`)
	str.WriteString("</p>")
	str.WriteString(`<pre id="error"></pre>`)

	w.Write([]byte(createHTML(str.String())))
}

func (n *nodeHandler) Delete(w http.ResponseWriter, r *http.Request) {
	hash := r.URL.Query().Get("hash")
	if hash == "" {
		http.Error(w, "hash is empty", http.StatusInternalServerError)
		return
	}

	_, err := n.nm.DeleteNode(context.TODO(), &wrapperspb.StringValue{Value: hash})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Write(nil)
}

func (n *nodeHandler) Post(w http.ResponseWriter, r *http.Request) {
	data, err := io.ReadAll(r.Body)
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

	_, err = n.nm.SaveNode(context.TODO(), point)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Write([]byte("successful"))
}

func (n *nodeHandler) Put(w http.ResponseWriter, r *http.Request) {
	hash := r.URL.Query().Get("hash")
	net := r.URL.Query().Get("net")

	req := &node.UseReq{Hash: hash}

	switch net {
	case "tcp":
		req.Tcp = true
	case "udp":
		req.Udp = true
	default:
		req.Tcp = true
		req.Udp = true
	}

	_, err := n.nm.Use(context.TODO(), req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Write(nil)
}
