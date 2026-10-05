package metrics

import (
	"os"
	"runtime"
	"sync"
	"time"

	"codeberg.org/miekg/dns/dnsutil"
	"github.com/Asutorufa/yuhaiin/pkg/utils/atomicx"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

type FlowCounter interface {
	LoadRunningDownload() uint64
	LoadRunningUpload() uint64
}

type flowCounterEmpty struct{}

func (c flowCounterEmpty) LoadRunningDownload() uint64 { return 0 }
func (c flowCounterEmpty) LoadRunningUpload() uint64   { return 0 }

var (
	flowCounter = atomicx.NewValue(FlowCounter(flowCounterEmpty{}))
	once        sync.Once
)

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
	AddReceiveUDPDroppedPacket()
	AddSendUDPDroppedPacket()
	AddReceiveUDPPacketSize(size int)
	AddSendUDPPacketSize(size int)
	AddConnection(addr string)
	AddGeoCountry(country string)
	AddBlockConnection(addr string)
	RemoveConnection(n int)
	AddStreamConnectDuration(t time.Duration)
	AddDNSProcess(domain string)
	AddLookupIP(t uint16)
	AddLookupIPFailed(rcode string, t uint16)
	AddTCPDialFailed(addr string)

	AddStreamRequest()
	AddPacketRequest()
	AddPingRequest()
	AddListenerNetworkRequest()
	AddListenerTransportRequest()
	AddHappyEyeballsv2DialRequest()
	AddHappyEyeballsIPsAttempted(int)
	AddDnsQueryDuration(string, time.Duration)
	AddDnsQuery(string)
	AddDnsQueryError(string)

	AddFakeIPCacheHit()
	AddFakeIPCacheMiss()

	AddTrieMatchDuration(time.Duration)
}

type EmptyMetrics struct{}

func (m *EmptyMetrics) AddReceiveUDPPacket()                      {}
func (m *EmptyMetrics) AddSendUDPPacket()                         {}
func (m *EmptyMetrics) AddReceiveUDPDroppedPacket()               {}
func (m *EmptyMetrics) AddSendUDPDroppedPacket()                  {}
func (m *EmptyMetrics) AddReceiveUDPPacketSize(int)               {}
func (m *EmptyMetrics) AddSendUDPPacketSize(int)                  {}
func (m *EmptyMetrics) AddConnection(string)                      {}
func (m *EmptyMetrics) AddBlockConnection(string)                 {}
func (m *EmptyMetrics) RemoveConnection(int)                      {}
func (m *EmptyMetrics) AddStreamConnectDuration(time.Duration)    {}
func (m *EmptyMetrics) AddDNSProcess(string)                      {}
func (m *EmptyMetrics) AddLookupIPFailed(string, uint16)          {}
func (m *EmptyMetrics) AddLookupIP(uint16)                        {}
func (m *EmptyMetrics) AddTCPDialFailed(string)                   {}
func (m *EmptyMetrics) AddStreamRequest()                         {}
func (m *EmptyMetrics) AddPacketRequest()                         {}
func (m *EmptyMetrics) AddPingRequest()                           {}
func (m *EmptyMetrics) AddListenerNetworkRequest()                {}
func (m *EmptyMetrics) AddListenerTransportRequest()              {}
func (m *EmptyMetrics) AddHappyEyeballsv2DialRequest()            {}
func (m *EmptyMetrics) AddDnsQueryDuration(string, time.Duration) {}
func (m *EmptyMetrics) AddDnsQueryError(string)                   {}
func (m *EmptyMetrics) AddDnsQuery(string)                        {}
func (m *EmptyMetrics) AddHappyEyeballsIPsAttempted(int)          {}
func (m *EmptyMetrics) AddFakeIPCacheHit()                        {}
func (m *EmptyMetrics) AddFakeIPCacheMiss()                       {}
func (m *EmptyMetrics) AddTrieMatchDuration(time.Duration)        {}
func (m *EmptyMetrics) AddGeoCountry(string)                      {}

type Prometheus struct {
	TotalReceiveUDPPacket        prometheus.Counter
	TotalSendUDPPacket           prometheus.Counter
	TotalReceiveUDPDroppedPacket prometheus.Counter
	TotalSendUDPDroppedPacket    prometheus.Counter
	UDPReceivePacketSize         prometheus.Histogram
	UDPSendPacketSize            prometheus.Histogram

	TotalStreamRequest              prometheus.Counter
	TotalPacketRequest              prometheus.Counter
	TotalPingRequest                prometheus.Counter
	TotalListenerNetworkRequest     prometheus.Counter
	TotalListenerTransportRequest   prometheus.Counter
	TotalHappyEyeballsv2DialRequest prometheus.Counter
	HappyEyeballsv2IPsAttempted     prometheus.Histogram

	TotalConnection      prometheus.Counter
	TotalGeoCountry      *prometheus.CounterVec
	CurrentConnection    prometheus.Gauge
	TotalBlockConnection prometheus.Counter

	StreamConnectDurationSeconds prometheus.Histogram
	StreamConnectSummarySeconds  prometheus.Summary

	DNSServerProcessTotal   prometheus.Counter
	LookupIPFailedTotal     *prometheus.CounterVec
	LookupIPTotal           *prometheus.CounterVec
	DNSQueryDurationSeconds *prometheus.HistogramVec
	DNSQueryErrorTotal      *prometheus.CounterVec
	DNSQueryTotal           *prometheus.CounterVec

	TCPDialFailedTotal prometheus.Counter

	FakeIPCacheHitTotal  prometheus.Counter
	FakeIPCacheMissTotal prometheus.Counter

	TrieMatchDurationSeconds prometheus.Histogram
}

func NewPrometheus() *Prometheus {
	return newPrometheus(prometheus.DefaultRegisterer)
}

func newPrometheus(registerer prometheus.Registerer) *Prometheus {
	factory := promauto.With(registerer)
	hostname, _ := os.Hostname()
	labels := prometheus.Labels{
		"hostname": hostname,
		"os":       runtime.GOOS,
		"arch":     runtime.GOARCH,
	}

	p := &Prometheus{
		TotalReceiveUDPPacket: factory.NewCounter(prometheus.CounterOpts{
			Name:        "yuhaiin_udp_receive_packets_total",
			Help:        "The total number of udp receive packets",
			ConstLabels: labels,
		}),
		TotalSendUDPPacket: factory.NewCounter(prometheus.CounterOpts{
			Name:        "yuhaiin_udp_send_packets_total",
			Help:        "The total number of udp send packets",
			ConstLabels: labels,
		}),
		TotalReceiveUDPDroppedPacket: factory.NewCounter(prometheus.CounterOpts{
			Name:        "yuhaiin_udp_receive_dropped_packets_total",
			Help:        "The total number of udp receive dropped packets",
			ConstLabels: labels,
		}),
		TotalSendUDPDroppedPacket: factory.NewCounter(prometheus.CounterOpts{
			Name:        "yuhaiin_udp_send_dropped_packets_total",
			Help:        "The total number of udp send dropped packets",
			ConstLabels: labels,
		}),
		UDPReceivePacketSize: factory.NewHistogram(prometheus.HistogramOpts{
			Name:        "yuhaiin_udp_receive_packet_size_bytes",
			Help:        "The size of udp receive packet",
			Buckets:     []float64{2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 1500, 2048, 4096, 8192, 16384, 32768, 65536},
			ConstLabels: labels,
		}),
		UDPSendPacketSize: factory.NewHistogram(prometheus.HistogramOpts{
			Name:        "yuhaiin_udp_send_packet_size_bytes",
			Help:        "The size of udp send packet",
			Buckets:     []float64{2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 1500, 2048, 4096, 8192, 16384, 32768, 65536},
			ConstLabels: labels,
		}),
		TotalStreamRequest: factory.NewCounter(prometheus.CounterOpts{
			Name:        "yuhaiin_stream_request_total",
			Help:        "The total number of stream request",
			ConstLabels: labels,
		}),
		TotalPacketRequest: factory.NewCounter(prometheus.CounterOpts{
			Name:        "yuhaiin_packet_request_total",
			Help:        "The total number of packet request",
			ConstLabels: labels,
		}),
		TotalPingRequest: factory.NewCounter(prometheus.CounterOpts{
			Name:        "yuhaiin_ping_request_total",
			Help:        "The total number of ping request",
			ConstLabels: labels,
		}),
		TotalListenerNetworkRequest: factory.NewCounter(prometheus.CounterOpts{
			Name:        "yuhaiin_listener_network_request_total",
			Help:        "The total number of listener network request",
			ConstLabels: labels,
		}),
		TotalListenerTransportRequest: factory.NewCounter(prometheus.CounterOpts{
			Name:        "yuhaiin_listener_transport_request_total",
			Help:        "The total number of listener transport request",
			ConstLabels: labels,
		}),
		TotalHappyEyeballsv2DialRequest: factory.NewCounter(prometheus.CounterOpts{
			Name:        "yuhaiin_happy_eyeballsv2_dial_request_total",
			Help:        "The total number of happy eyeballv2 dial request",
			ConstLabels: labels,
		}),
		HappyEyeballsv2IPsAttempted: factory.NewHistogram(prometheus.HistogramOpts{
			Name:        "yuhaiin_happy_eyeballsv2_ip_attempts",
			Help:        "The number of happy eyeballv2 ip attempts for each dial request",
			ConstLabels: labels,
			Buckets:     []float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 14, 18, 20},
		}),

		TotalConnection: factory.NewCounter(prometheus.CounterOpts{
			Name:        "yuhaiin_connection_total",
			Help:        "The total number of connections",
			ConstLabels: labels,
		}),
		TotalGeoCountry: factory.NewCounterVec(prometheus.CounterOpts{
			Name:        "yuhaiin_request_geo_country_total",
			Help:        "The total number of requests by country",
			ConstLabels: labels,
		}, []string{"country"}),
		CurrentConnection: factory.NewGauge(prometheus.GaugeOpts{
			Name:        "yuhaiin_connection_current",
			Help:        "The current number of connections",
			ConstLabels: labels,
		}),
		TotalBlockConnection: factory.NewCounter(prometheus.CounterOpts{
			Name:        "yuhaiin_block_connection_total",
			Help:        "The total number of block connections",
			ConstLabels: labels,
		}),
		StreamConnectDurationSeconds: factory.NewHistogram(prometheus.HistogramOpts{
			Name:        "yuhaiin_stream_connect_duration_seconds",
			Help:        "The duration of tcp connect",
			Buckets:     []float64{0.05, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1, 1.5, 2, 2.5, 3, 5, 10},
			ConstLabels: labels,
		}),
		StreamConnectSummarySeconds: factory.NewSummary(prometheus.SummaryOpts{
			Name:        "yuhaiin_stream_connect_summary_seconds",
			Help:        "The summary of tcp connect",
			ConstLabels: labels,
		}),
		DNSServerProcessTotal: factory.NewCounter(prometheus.CounterOpts{
			Name:        "yuhaiin_dns_server_process_total",
			Help:        "The total number of dns process",
			ConstLabels: labels,
		}),
		LookupIPFailedTotal: factory.NewCounterVec(prometheus.CounterOpts{
			Name:        "yuhaiin_dns_lookup_ip_failed_total",
			Help:        "The total number of dns lookup ip failed",
			ConstLabels: labels,
		}, []string{"rcode", "type"}),
		LookupIPTotal: factory.NewCounterVec(prometheus.CounterOpts{
			Name:        "yuhaiin_dns_lookup_ip_total",
			Help:        "The total number of dns lookup ip",
			ConstLabels: labels,
		}, []string{"type"}),
		DNSQueryDurationSeconds: factory.NewHistogramVec(prometheus.HistogramOpts{
			Name:        "yuhaiin_dns_query_duration_seconds",
			Help:        "The duration of dns query",
			Buckets:     []float64{0.05, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1, 1.5, 2, 2.5, 3, 5, 10},
			ConstLabels: labels,
		}, []string{"name"}),
		DNSQueryTotal: factory.NewCounterVec(prometheus.CounterOpts{
			Name:        "yuhaiin_dns_query_total",
			Help:        "The total number of dns query",
			ConstLabels: labels,
		}, []string{"name"}),
		DNSQueryErrorTotal: factory.NewCounterVec(prometheus.CounterOpts{
			Name:        "yuhaiin_dns_query_error_total",
			Help:        "The total number of dns query error",
			ConstLabels: labels,
		}, []string{"name"}),
		TCPDialFailedTotal: factory.NewCounter(prometheus.CounterOpts{
			Name:        "yuhaiin_tcp_dial_failed_total",
			Help:        "The total number of tcp dial failed",
			ConstLabels: labels,
		}),

		FakeIPCacheHitTotal: factory.NewCounter(prometheus.CounterOpts{
			Name:        "yuhaiin_fake_ip_cache_hit_total",
			Help:        "The total number of fake ip cache hit",
			ConstLabels: labels,
		}),
		FakeIPCacheMissTotal: factory.NewCounter(prometheus.CounterOpts{
			Name:        "yuhaiin_fake_ip_cache_miss_total",
			Help:        "The total number of fake ip cache miss",
			ConstLabels: labels,
		}),

		TrieMatchDurationSeconds: factory.NewHistogram(prometheus.HistogramOpts{
			Name:        "yuhaiin_trie_match_duration_seconds",
			Help:        "The duration of trie match",
			Buckets:     []float64{0.000005, 0.00001, 0.00002, 0.00005, 0.0001, 0.0002, 0.0005, 0.001, 0.002, 0.005, 0.01, 0.1, 1},
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

func (p *Prometheus) AddStreamConnectDuration(t time.Duration) {
	p.StreamConnectDurationSeconds.Observe(t.Seconds())
	p.StreamConnectSummarySeconds.Observe(t.Seconds())
}

func (p *Prometheus) AddDNSProcess(domain string) {
	p.DNSServerProcessTotal.Inc()
}

func (p *Prometheus) AddLookupIPFailed(rcode string, t uint16) {
	p.LookupIPFailedTotal.WithLabelValues(rcode, dnsutil.TypeToString(t)).Inc()
}

func (p *Prometheus) AddLookupIP(t uint16) {
	p.LookupIPTotal.WithLabelValues(dnsutil.TypeToString(t)).Inc()
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

func (p *Prometheus) AddReceiveUDPDroppedPacket() {
	p.TotalReceiveUDPDroppedPacket.Inc()
}

func (p *Prometheus) AddSendUDPDroppedPacket() {
	p.TotalSendUDPDroppedPacket.Inc()
}

func (p *Prometheus) AddReceiveUDPPacketSize(size int) {
	p.UDPReceivePacketSize.Observe(float64(size))
}

func (p *Prometheus) AddSendUDPPacketSize(size int) {
	p.UDPSendPacketSize.Observe(float64(size))
}

func (p *Prometheus) AddStreamRequest() {
	p.TotalStreamRequest.Inc()
}

func (p *Prometheus) AddPacketRequest() {
	p.TotalPacketRequest.Inc()
}

func (p *Prometheus) AddPingRequest() {
	p.TotalPingRequest.Inc()
}

func (p *Prometheus) AddListenerNetworkRequest() {
	p.TotalListenerNetworkRequest.Inc()
}

func (p *Prometheus) AddListenerTransportRequest() {
	p.TotalListenerTransportRequest.Inc()
}

func (p *Prometheus) AddHappyEyeballsv2DialRequest() {
	p.TotalHappyEyeballsv2DialRequest.Inc()
}

func (p *Prometheus) AddDnsQueryDuration(name string, t time.Duration) {
	p.DNSQueryDurationSeconds.WithLabelValues(name).Observe(t.Seconds())
}

func (p *Prometheus) AddDnsQuery(name string) {
	p.DNSQueryTotal.WithLabelValues(name).Inc()
}

func (p *Prometheus) AddDnsQueryError(name string) {
	p.DNSQueryErrorTotal.WithLabelValues(name).Inc()
}

func (p *Prometheus) AddHappyEyeballsIPsAttempted(count int) {
	p.HappyEyeballsv2IPsAttempted.Observe(float64(count))
}

func (p *Prometheus) AddFakeIPCacheHit() {
	p.FakeIPCacheHitTotal.Inc()
}

func (p *Prometheus) AddFakeIPCacheMiss() {
	p.FakeIPCacheMissTotal.Inc()
}

func (p *Prometheus) AddTrieMatchDuration(t time.Duration) {
	p.TrieMatchDurationSeconds.Observe(t.Seconds())
}

func (p *Prometheus) AddGeoCountry(country string) {
	p.TotalGeoCountry.WithLabelValues(country).Inc()
}
