package simplehttp

import (
	"net/http"
	"unsafe"

	tps "github.com/Asutorufa/yuhaiin/internal/http/templates"
	grpcnode "github.com/Asutorufa/yuhaiin/pkg/protos/node/grpc"
	"google.golang.org/protobuf/encoding/protojson"
)

type rootHandler struct {
	emptyHTTP
	nm grpcnode.NodeServer
}

func (z *rootHandler) Get(w http.ResponseWriter, r *http.Request) error {
	point, err := z.nm.Now(r.Context(), &grpcnode.NowReq{Net: grpcnode.NowReq_tcp})
	if err != nil {
		return err
	}
	tcpData, err := protojson.MarshalOptions{Indent: "  "}.Marshal(point)
	if err != nil {
		return err
	}

	point, err = z.nm.Now(r.Context(), &grpcnode.NowReq{Net: grpcnode.NowReq_udp})
	if err != nil {
		return err
	}
	udpData, err := protojson.MarshalOptions{Indent: "  "}.Marshal(point)
	if err != nil {
		return err
	}
	return TPS.BodyExecute(w, map[string]any{
		"TCP": unsafe.String(&tcpData[0], len(tcpData)),
		"UDP": unsafe.String(&udpData[0], len(udpData)),
	}, tps.ROOT)
}
