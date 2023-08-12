package latency

import (
	"github.com/Asutorufa/yuhaiin/pkg/net/latency"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	durationpb "google.golang.org/protobuf/types/known/durationpb"
)

func (l *Protocol_Http) Latency(p netapi.Proxy) (*durationpb.Duration, error) {
	t, err := latency.HTTP(p, l.Http.GetUrl())
	return durationpb.New(t), err
}

func (l *Protocol_Dns) Latency(p netapi.Proxy) (*durationpb.Duration, error) {
	t, err := latency.DNS(p, l.Dns.GetHost(), l.Dns.GetTargetDomain())
	return durationpb.New(t), err
}

func (l *Protocol_DnsOverQuic) Latency(p netapi.Proxy) (*durationpb.Duration, error) {
	t, err := latency.DNSOverQuic(p, l.DnsOverQuic.Host, l.DnsOverQuic.TargetDomain)
	return durationpb.New(t), err
}
