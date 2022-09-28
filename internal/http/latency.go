package simplehttp

import (
	"context"
	"errors"
	"net/http"

	grpcnode "github.com/Asutorufa/yuhaiin/pkg/protos/node/grpc"
)

type latencyHandler struct {
	emptyHTTP
	nm grpcnode.NodeManagerServer
}

func (l *latencyHandler) Get(w http.ResponseWriter, r *http.Request) error {
	hash := r.URL.Query().Get("hash")
	t := r.URL.Query().Get("type")

	req := &grpcnode.LatencyReqRequest{Hash: hash}

	if t == "tcp" {
		req.Protocols = append(req.Protocols, &grpcnode.LatencyReqRequestProtocol{
			Protocol: &grpcnode.LatencyReqRequestProtocol_Http{
				Http: &grpcnode.LatencyReqHttp{
					Url: "https://clients3.google.com/generate_204",
				},
			},
		})
	}

	if t == "udp" {
		req.Protocols = append(req.Protocols, &grpcnode.LatencyReqRequestProtocol{
			Protocol: &grpcnode.LatencyReqRequestProtocol_Dns{
				Dns: &grpcnode.LatencyReqDns{
					Host:         "1.1.1.1:53",
					TargetDomain: "www.google.com",
				},
			},
		})
	}

	lt, err := l.nm.Latency(context.TODO(), &grpcnode.LatencyReq{Requests: []*grpcnode.LatencyReqRequest{req}})

	if err != nil {
		return err
	}
	if _, ok := lt.HashLatencyMap[hash]; !ok {
		return errors.New("test latency timeout or can't connect")
	}

	var resp string
	if lt.HashLatencyMap[hash] != nil {
		resp = lt.HashLatencyMap[hash].Times[0].AsDuration().String()
	}

	w.Write([]byte(resp))

	return nil
}
