package metrics

import (
	"os"
	"runtime"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/utils/atomicx"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"golang.org/x/net/dns/dnsmessage"
)

type FlowCounter interface {
	LoadRunningDownload() uint64
	LoadRunningUpload() uint64
}

type flowCounterEmpty struct{}

func (c flowCounterEmpty) LoadRunningDownload() uint64 { return 0 }
func (c flowCounterEmpty) LoadRunningUpload() uint64   { return 0 }

var flowCounter = atomicx.NewValue(FlowCounter(flowCounterEmpty{}))
var once sync.Once

func SetFlowCounter(c FlowCounter) {
	flowCounter.Store(c)

	once.Do(func() {
		hostname, _ := os.Hostname()
		labels := prometheus.Labels{
			"hostname": hostname,
			"os":       runtime.GOOS,
			"arch":     runtime.GOARCH,
		}

		Counter = NewPrometheus()

		promauto.NewCounterFunc(prometheus.CounterOpts{
			Name:        "yuhaiin_download_bytes_total",
			Help:        "The total number of download bytes",
			ConstLabels: labels,
		}, func() float64 { return float64(flowCounter.Load().LoadRunningDownload()) })

		promauto.NewCounterFunc(prometheus.CounterOpts{
			Name:        "yuhaiin_upload_bytes_total",
			Help:        "The total number of upload bytes",
			ConstLabels: labels,
		}, func() float64 { return float64(flowCounter.Load().LoadRunningUpload()) })
	})
}

var Counter Metrics = &EmptyMetrics{}

type Metrics interface {
	AddReceiveUDPPacket()
	AddSendUDPPacket()
	AddConnection(addr string)
	AddBlockConnection(addr string)
	RemoveConnection(n int)
	AddStreamConnectDuration(t float64)
	AddDNSProcess(domain string)
	AddFailedDNS(domain string, rcode dnsmessage.RCode, t dnsmessage.Type)
	AddTCPDialFailed(addr string)
}

type EmptyMetrics struct{}

func (m *EmptyMetrics) AddReceiveUDPPacket()                                                  {}
func (m *EmptyMetrics) AddSendUDPPacket()                                                     {}
func (m *EmptyMetrics) AddConnection(addr string)                                             {}
func (m *EmptyMetrics) AddBlockConnection(addr string)                                        {}
func (m *EmptyMetrics) RemoveConnection(n int)                                                {}
func (m *EmptyMetrics) AddStreamConnectDuration(t float64)                                    {}
func (m *EmptyMetrics) AddDNSProcess(domain string)                                           {}
func (m *EmptyMetrics) AddFailedDNS(domain string, rcode dnsmessage.RCode, t dnsmessage.Type) {}
func (m *EmptyMetrics) AddTCPDialFailed(addr string)                                          {}

type Prometheus struct {
	TotalReceiveUDPPacket prometheus.Counter
	TotalSendUDPPacket    prometheus.Counter
	TotalConnection       prometheus.Counter
	CurrentConnection     prometheus.Gauge
	TotalBlockConnection  prometheus.Counter

	StreamConnectDurationSeconds prometheus.Histogram
	StreamConnectSummarySeconds  prometheus.Summary

	DNSProcessTotal prometheus.Counter
	FiledDNSTotal   prometheus.Counter

	TCPDialFailedTotal prometheus.Counter
}

func NewPrometheus() *Prometheus {
	hostname, _ := os.Hostname()
	labels := prometheus.Labels{
		"hostname": hostname,
		"os":       runtime.GOOS,
		"arch":     runtime.GOARCH,
	}

	p := &Prometheus{
		TotalReceiveUDPPacket: promauto.NewCounter(prometheus.CounterOpts{
			Name:        "yuhaiin_udp_receive_packets_total",
			Help:        "The total number of udp receive packets",
			ConstLabels: labels,
		}),
		TotalSendUDPPacket: promauto.NewCounter(prometheus.CounterOpts{
			Name:        "yuhaiin_udp_send_packets_total",
			Help:        "The total number of udp send packets",
			ConstLabels: labels,
		}),
		TotalConnection: promauto.NewCounter(prometheus.CounterOpts{
			Name:        "yuhaiin_connection_total",
			Help:        "The total number of connections",
			ConstLabels: labels,
		}),
		CurrentConnection: promauto.NewGauge(prometheus.GaugeOpts{
			Name:        "yuhaiin_connection_current",
			Help:        "The current number of connections",
			ConstLabels: labels,
		}),
		TotalBlockConnection: promauto.NewCounter(prometheus.CounterOpts{
			Name:        "yuhaiin_block_connection_total",
			Help:        "The total number of block connections",
			ConstLabels: labels,
		}),
		StreamConnectDurationSeconds: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:        "yuhaiin_stream_connect_duration_seconds",
			Help:        "The duration of tcp connect",
			ConstLabels: labels,
		}),
		StreamConnectSummarySeconds: promauto.NewSummary(prometheus.SummaryOpts{
			Name:        "yuhaiin_stream_connect_summary_seconds",
			Help:        "The summary of tcp connect",
			ConstLabels: labels,
		}),
		DNSProcessTotal: promauto.NewCounter(prometheus.CounterOpts{
			Name:        "yuhaiin_dns_process_total",
			Help:        "The total number of dns process",
			ConstLabels: labels,
		}),
		FiledDNSTotal: promauto.NewCounter(prometheus.CounterOpts{
			Name:        "yuhaiin_dns_request_failed_total",
			Help:        "The total number of dns request failed",
			ConstLabels: labels,
		}),
		TCPDialFailedTotal: promauto.NewCounter(prometheus.CounterOpts{
			Name:        "yuhaiin_tcp_dial_failed_total",
			Help:        "The total number of tcp dial failed",
			ConstLabels: labels,
		}),
	}

	return p
}

func (p *Prometheus) AddConnection(addr string) {
	p.TotalConnection.Inc()
	p.CurrentConnection.Inc()
}

func (p *Prometheus) AddBlockConnection(addr string) {
	p.TotalBlockConnection.Inc()
}

func (p *Prometheus) RemoveConnection(n int) {
	p.CurrentConnection.Sub(float64(n))
}

func (p *Prometheus) AddStreamConnectDuration(t float64) {
	p.StreamConnectDurationSeconds.Observe(t)
	p.StreamConnectSummarySeconds.Observe(t)
}

func (p *Prometheus) AddDNSProcess(domain string) {
	p.DNSProcessTotal.Inc()
}

func (p *Prometheus) AddFailedDNS(domain string, rcode dnsmessage.RCode, t dnsmessage.Type) {
	p.FiledDNSTotal.Inc()
}

func (p *Prometheus) AddTCPDialFailed(addr string) {
	p.TCPDialFailedTotal.Inc()
}

func (p *Prometheus) AddReceiveUDPPacket() {
	p.TotalReceiveUDPPacket.Inc()
}

func (p *Prometheus) AddSendUDPPacket() {
	p.TotalSendUDPPacket.Inc()
}
