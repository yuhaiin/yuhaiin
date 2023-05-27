package latency

import (
	proxy "github.com/Asutorufa/yuhaiin/pkg/net/interfaces"
	"github.com/Asutorufa/yuhaiin/pkg/net/latency"
	durationpb "google.golang.org/protobuf/types/known/durationpb"
)

func (l *Protocol_Http) Latency(p proxy.Proxy) (*durationpb.Duration, error) {
	t, err := latency.HTTP(p, l.Http.GetUrl())
	return durationpb.New(t), err
}

func (l *Protocol_Dns) Latency(p proxy.Proxy) (*durationpb.Duration, error) {
	t, err := latency.DNS(p, l.Dns.GetHost(), l.Dns.GetTargetDomain())
	return durationpb.New(t), err
}

func (l *Protocol_DnsOverQuic) Latency(p proxy.Proxy) (*durationpb.Duration, error) {
	t, err := latency.DNSOverQuic(p, l.DnsOverQuic.Host, l.DnsOverQuic.TargetDomain)
	return durationpb.New(t), err
}
