package metrics

import (
	"os"
	"runtime"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"golang.org/x/net/dns/dnsmessage"
)

var Counter Metrics = NewPrometheus()

type Metrics interface {
	AddDownload(n int)
	AddUpload(n int)
	AddReceiveUDPPacket()
	AddSendUDPPacket()
	AddConnection(addr string)
	RemoveConnection(n int)
	AddStreamConnectDuration(t float64)
	AddDNSProcess(domain string)
	AddFailedDNS(domain string, rcode dnsmessage.RCode, t dnsmessage.Type)
	AddTCPDialFailed(addr string)
}

type Prometheus struct {
	TotalDownload         prometheus.Counter
	TotalUpload           prometheus.Counter
	TotalReceiveUDPPacket prometheus.Counter
	TotalSendUDPPacket    prometheus.Counter
	TotalConnection       *prometheus.CounterVec
	CurrentConnection     prometheus.Gauge

	StreamConnectDurationSeconds prometheus.Histogram
	StreamConnectSummarySeconds  prometheus.Summary

	DNSProcessTotal *prometheus.CounterVec
	FiledDNSTotal   *prometheus.CounterVec

	TCPDialFailedTotal *prometheus.CounterVec
}

func NewPrometheus() *Prometheus {
	hostname, _ := os.Hostname()
	labels := prometheus.Labels{
		"hostname": hostname,
		"os":       runtime.GOOS,
		"arch":     runtime.GOARCH,
	}

	p := &Prometheus{
		TotalDownload: promauto.NewCounter(prometheus.CounterOpts{
			Name:        "yuhaiin_download_bytes_total",
			Help:        "The total number of download bytes",
			ConstLabels: labels,
		}),
		TotalUpload: promauto.NewCounter(prometheus.CounterOpts{
			Name:        "yuhaiin_upload_bytes_total",
			Help:        "The total number of upload bytes",
			ConstLabels: labels,
		}),
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
		TotalConnection: promauto.NewCounterVec(prometheus.CounterOpts{
			Name:        "yuhaiin_connection_total",
			Help:        "The total number of connections",
			ConstLabels: labels,
		}, []string{"address"}),
		CurrentConnection: promauto.NewGauge(prometheus.GaugeOpts{
			Name:        "yuhaiin_connection_current",
			Help:        "The current number of connections",
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
		DNSProcessTotal: promauto.NewCounterVec(prometheus.CounterOpts{
			Name:        "yuhaiin_dns_process_total",
			Help:        "The total number of dns process",
			ConstLabels: labels,
		}, []string{"domain"}),
		FiledDNSTotal: promauto.NewCounterVec(prometheus.CounterOpts{
			Name:        "yuhaiin_dns_request_failed_total",
			Help:        "The total number of dns request failed",
			ConstLabels: labels,
		}, []string{"domain", "rcode", "dns_type"}),
		TCPDialFailedTotal: promauto.NewCounterVec(prometheus.CounterOpts{
			Name:        "yuhaiin_tcp_dial_failed_total",
			Help:        "The total number of tcp dial failed",
			ConstLabels: labels,
		}, []string{"address"}),
	}

	var timer *time.Timer
	timer = time.AfterFunc(time.Hour*2, func() {
		p.DNSProcessTotal.Reset()
		p.FiledDNSTotal.Reset()
		p.TotalConnection.Reset()
		p.TCPDialFailedTotal.Reset()
		timer.Reset(time.Hour * 2)
	})

	return p
}

func (p *Prometheus) AddDownload(n int) {
	p.TotalDownload.Add(float64(n))
}

func (p *Prometheus) AddUpload(n int) {
	p.TotalUpload.Add(float64(n))
}

func (p *Prometheus) AddConnection(addr string) {
	p.TotalConnection.With(prometheus.Labels{"address": addr}).Inc()
	p.CurrentConnection.Inc()
}

func (p *Prometheus) RemoveConnection(n int) {
	p.CurrentConnection.Sub(float64(n))
}

func (p *Prometheus) AddStreamConnectDuration(t float64) {
	p.StreamConnectDurationSeconds.Observe(t)
	p.StreamConnectSummarySeconds.Observe(t)
}

func (p *Prometheus) AddDNSProcess(domain string) {
	p.DNSProcessTotal.With(prometheus.Labels{"domain": domain}).Inc()
}

func (p *Prometheus) AddFailedDNS(domain string, rcode dnsmessage.RCode, t dnsmessage.Type) {
	p.FiledDNSTotal.With(prometheus.Labels{
		"domain":   domain,
		"rcode":    rcode.String(),
		"dns_type": t.String(),
	}).Inc()
}

func (p *Prometheus) AddTCPDialFailed(addr string) {
	p.TCPDialFailedTotal.With(prometheus.Labels{"address": addr}).Inc()
}

func (p *Prometheus) AddReceiveUDPPacket() {
	p.TotalReceiveUDPPacket.Inc()
}

func (p *Prometheus) AddSendUDPPacket() {
	p.TotalSendUDPPacket.Inc()
}
