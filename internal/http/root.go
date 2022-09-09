package simplehttp

import (
	"context"
	"net/http"
	"unsafe"

	tps "github.com/Asutorufa/yuhaiin/internal/http/templates"
	grpcnode "github.com/Asutorufa/yuhaiin/pkg/protos/grpc/node"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	"google.golang.org/protobuf/encoding/protojson"
)

type rootHandler struct {
	emptyHTTP
	nm grpcnode.NodeManagerServer
}

func (z *rootHandler) Get(w http.ResponseWriter, r *http.Request) error {
	point, err := z.nm.Now(context.TODO(), &node.NowReq{Net: node.NowReq_tcp})
	if err != nil {
		return err
	}
	tcpData, err := protojson.MarshalOptions{Indent: "  "}.Marshal(point)
	if err != nil {
		return err
	}

	point, err = z.nm.Now(context.TODO(), &node.NowReq{Net: node.NowReq_udp})
	if err != nil {
		return err
	}
	udpData, err := protojson.MarshalOptions{Indent: "  "}.Marshal(point)
	if err != nil {
		return err
	}
	return TPS.BodyExecute(w, map[string]any{
		"TCP": *(*string)(unsafe.Pointer(&tcpData)),
		"UDP": *(*string)(unsafe.Pointer(&udpData)),
	}, tps.ROOT)
}
