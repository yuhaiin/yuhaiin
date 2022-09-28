package service

import (
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/latency"
	"google.golang.org/protobuf/types/known/durationpb"
)

func (l *LatencyReqRequestProtocol_Http) Latency(p proxy.Proxy) (*durationpb.Duration, error) {
	t, err := latency.HTTP(p, l.Http.GetUrl())
	return durationpb.New(t), err
}

func (l *LatencyReqRequestProtocol_Dns) Latency(p proxy.Proxy) (*durationpb.Duration, error) {
	t, err := latency.DNS(p, l.Dns.GetHost(), l.Dns.GetTargetDomain())
	return durationpb.New(t), err
}
