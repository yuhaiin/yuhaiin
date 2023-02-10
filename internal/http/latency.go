package simplehttp

import (
	"context"
	"errors"
	"net/http"

	grpcnode "github.com/Asutorufa/yuhaiin/pkg/protos/node/grpc"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/latency"
	"google.golang.org/protobuf/types/known/durationpb"
)

type latencyHandler struct {
	emptyHTTP
	nm grpcnode.NodeServer
}

func (l *latencyHandler) udp(r *http.Request) *latency.Request {
	hash := r.URL.Query().Get("hash")
	return &latency.Request{
		Id:   "udp",
		Hash: hash,
		Protocol: &latency.Protocol{
			Protocol: &latency.Protocol_DnsOverQuic{
				DnsOverQuic: &latency.DnsOverQuic{
					Host:         "dns.nextdns.io:853",
					TargetDomain: "www.google.com",
				},
			},
			// Protocol: &latency.Protocol_Dns{
			// 	Dns: &latency.Dns{
			// 		Host:         "8.8.8.8",
			// 		TargetDomain: "www.google.com",
			// 	},
			// },
		},
	}
}

func (l *latencyHandler) tcp(r *http.Request) *latency.Request {
	hash := r.URL.Query().Get("hash")
	return &latency.Request{
		Id:   "tcp",
		Hash: hash,
		Protocol: &latency.Protocol{
			Protocol: &latency.Protocol_Http{
				Http: &latency.Http{
					Url: "https://clients3.google.com/generate_204",
				},
			},
		},
	}
}

func (l *latencyHandler) Get(w http.ResponseWriter, r *http.Request) error {
	t := r.URL.Query().Get("type")

	req := &latency.Requests{}
	if t == "tcp" {
		req.Requests = append(req.Requests, l.tcp(r))
	}

	if t == "udp" {
		req.Requests = append(req.Requests, l.udp(r))
	}

	lt, err := l.nm.Latency(context.TODO(), req)
	if err != nil {
		return err
	}

	var tt *durationpb.Duration
	if z, ok := lt.IdLatencyMap["tcp"]; ok {
		tt = z
	} else if z, ok := lt.IdLatencyMap["udp"]; ok {
		tt = z
	}

	if tt == nil || tt.AsDuration() == 0 {
		return errors.New("test latency timeout or can't connect")
	}

	w.Write([]byte(tt.AsDuration().String()))

	return nil
}
