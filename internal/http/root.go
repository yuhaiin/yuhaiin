package simplehttp

import (
	"encoding/json"
	"net/http"

	grpcnode "github.com/Asutorufa/yuhaiin/pkg/protos/node/grpc"
	"google.golang.org/protobuf/encoding/protojson"
)

type rootHandler struct {
	nm grpcnode.NodeServer
}

func (z *rootHandler) NodeNow(w http.ResponseWriter, r *http.Request) error {
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

	data, err := json.Marshal(map[string]string{
		"tcp": string(tcpData),
		"udp": string(udpData),
	})
	if err != nil {
		return err
	}

	_, err = w.Write(data)
	return err
}
