package simplehttp

import (
	"context"
	"errors"
	"net/http"

	grpcnode "github.com/Asutorufa/yuhaiin/pkg/protos/grpc/node"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
)

type latencyHandler struct {
	emptyHTTP
	nm grpcnode.NodeManagerServer
}

func (l *latencyHandler) Get(w http.ResponseWriter, r *http.Request) error {
	hash := r.URL.Query().Get("hash")
	t := r.URL.Query().Get("type")
	lt, err := l.nm.Latency(context.TODO(), &node.LatencyReq{
		Requests: []*node.LatencyReqRequest{{Hash: hash, Tcp: t == "tcp", Udp: t == "udp"}}})
	if err != nil {
		return err
	}
	if _, ok := lt.HashLatencyMap[hash]; !ok {
		return errors.New("test latency timeout or can't connect")
	}

	var resp string
	if t == "tcp" {
		resp = lt.HashLatencyMap[hash].Tcp
	} else if t == "udp" {
		resp = lt.HashLatencyMap[hash].Udp
	}

	w.Write([]byte(resp))

	return nil
}
