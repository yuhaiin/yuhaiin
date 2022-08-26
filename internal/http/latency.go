package simplehttp

import (
	"context"
	"net/http"

	grpcnode "github.com/Asutorufa/yuhaiin/pkg/protos/grpc/node"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
)

type latencyHandler struct {
	emptyHTTP
	nm grpcnode.NodeManagerServer
}

func (l *latencyHandler) Get(w http.ResponseWriter, r *http.Request) {
	hash := r.URL.Query().Get("hash")
	t := r.URL.Query().Get("type")
	lt, err := l.nm.Latency(context.TODO(), &node.LatencyReq{
		Requests: []*node.LatencyReqRequest{{Hash: hash, Tcp: t == "tcp", Udp: t == "udp"}}})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if _, ok := lt.HashLatencyMap[hash]; !ok {
		http.Error(w, "test latency timeout or can't connect", http.StatusInternalServerError)
		return
	}

	var resp string
	if t == "tcp" {
		resp = lt.HashLatencyMap[hash].Tcp
	} else if t == "udp" {
		resp = lt.HashLatencyMap[hash].Udp
	}

	w.Write([]byte(resp))
}
