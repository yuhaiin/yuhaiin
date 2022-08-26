package simplehttp

import (
	"context"
	"net/http"

	"github.com/Asutorufa/yuhaiin/pkg/net/utils"
	grpcnode "github.com/Asutorufa/yuhaiin/pkg/protos/grpc/node"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	"google.golang.org/protobuf/encoding/protojson"
)

type rootHandler struct {
	emptyHTTP
	nm grpcnode.NodeManagerServer
}

func (z *rootHandler) Get(w http.ResponseWriter, r *http.Request) {
	point, err := z.nm.Now(context.TODO(), &node.NowReq{Net: node.NowReq_tcp})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tcpData, err := protojson.MarshalOptions{Indent: "  "}.Marshal(point)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	point, err = z.nm.Now(context.TODO(), &node.NowReq{Net: node.NowReq_udp})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	udpData, err := protojson.MarshalOptions{Indent: "  "}.Marshal(point)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	str := utils.GetBuffer()
	defer utils.PutBuffer(str)

	str.WriteString("TCP")
	str.WriteString("<pre>")
	str.Write(tcpData)
	str.WriteString("</pre>")
	str.WriteString("<hr/>")
	str.WriteString("UDP")
	str.WriteString("<pre>")
	str.Write(udpData)
	str.WriteString("</pre>")

	w.Write([]byte(createHTML(str.String())))
}
