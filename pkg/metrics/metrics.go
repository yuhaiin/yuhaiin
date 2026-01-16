package metrics

import (
	"os"
	"runtime"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/utils/atomicx"
	"github.com/miekg/dns"
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
	AddStreamConnectDuration(t float64)
	AddDNSProcess(domain string)
	AddLookupIP(t dns.Type)
	AddLookupIPFailed(rcode string, t dns.Type)
	AddTCPDialFailed(addr string)

	AddStreamRequest()
	AddPacketRequest()
	AddPingRequest()
	AddListenerNetworkRequest()
	AddListenerTransportRequest()
	AddHappyEyeballsv2DialRequest()
	AddHappyEyeballsIPsAttempted(int)
	AddDnsQueryDuration(string, float64)
	AddDnsQuery(string)
	AddDnsQueryError(string)

	AddFakeIPCacheHit()
	AddFakeIPCacheMiss()

	AddTrieMatchDuration(float64)
}

type EmptyMetrics struct{}

func (m *EmptyMetrics) AddReceiveUDPPacket()                {}
func (m *EmptyMetrics) AddSendUDPPacket()                   {}
func (m *EmptyMetrics) AddReceiveUDPDroppedPacket()         {}
func (m *EmptyMetrics) AddSendUDPDroppedPacket()            {}
func (m *EmptyMetrics) AddReceiveUDPPacketSize(int)         {}
func (m *EmptyMetrics) AddSendUDPPacketSize(int)            {}
func (m *EmptyMetrics) AddConnection(string)                {}
func (m *EmptyMetrics) AddBlockConnection(string)           {}
func (m *EmptyMetrics) RemoveConnection(int)                {}
func (m *EmptyMetrics) AddStreamConnectDuration(float64)    {}
func (m *EmptyMetrics) AddDNSProcess(string)                {}
func (m *EmptyMetrics) AddLookupIPFailed(string, dns.Type)  {}
func (m *EmptyMetrics) AddLookupIP(dns.Type)                {}
func (m *EmptyMetrics) AddTCPDialFailed(string)             {}
func (m *EmptyMetrics) AddStreamRequest()                   {}
func (m *EmptyMetrics) AddPacketRequest()                   {}
func (m *EmptyMetrics) AddPingRequest()                     {}
func (m *EmptyMetrics) AddListenerNetworkRequest()          {}
func (m *EmptyMetrics) AddListenerTransportRequest()        {}
func (m *EmptyMetrics) AddHappyEyeballsv2DialRequest()      {}
func (m *EmptyMetrics) AddDnsQueryDuration(string, float64) {}
func (m *EmptyMetrics) AddDnsQueryError(string)             {}
func (m *EmptyMetrics) AddDnsQuery(string)                  {}
func (m *EmptyMetrics) AddHappyEyeballsIPsAttempted(int)    {}
func (m *EmptyMetrics) AddFakeIPCacheHit()                  {}
func (m *EmptyMetrics) AddFakeIPCacheMiss()                 {}
func (m *EmptyMetrics) AddTrieMatchDuration(float64)        {}
func (m *EmptyMetrics) AddGeoCountry(string)                {}

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
		TotalReceiveUDPDroppedPacket: promauto.NewCounter(prometheus.CounterOpts{
			Name:        "yuhaiin_udp_receive_dropped_packets_total",
			Help:        "The total number of udp receive dropped packets",
			ConstLabels: labels,
		}),
		TotalSendUDPDroppedPacket: promauto.NewCounter(prometheus.CounterOpts{
			Name:        "yuhaiin_udp_send_dropped_packets_total",
			Help:        "The total number of udp send dropped packets",
			ConstLabels: labels,
		}),
		UDPReceivePacketSize: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:        "yuhaiin_udp_receive_packet_size_bytes",
			Help:        "The size of udp receive packet",
			Buckets:     []float64{2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 1500, 2048, 4096, 8192, 16384, 32768, 65536},
			ConstLabels: labels,
		}),
		UDPSendPacketSize: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:        "yuhaiin_udp_send_packet_size_bytes",
			Help:        "The size of udp send packet",
			Buckets:     []float64{2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 1500, 2048, 4096, 8192, 16384, 32768, 65536},
			ConstLabels: labels,
		}),
		TotalStreamRequest: promauto.NewCounter(prometheus.CounterOpts{
			Name:        "yuhaiin_stream_request_total",
			Help:        "The total number of stream request",
			ConstLabels: labels,
		}),
		TotalPacketRequest: promauto.NewCounter(prometheus.CounterOpts{
			Name:        "yuhaiin_packet_request_total",
			Help:        "The total number of packet request",
			ConstLabels: labels,
		}),
		TotalPingRequest: promauto.NewCounter(prometheus.CounterOpts{
			Name:        "yuhaiin_ping_request_total",
			Help:        "The total number of ping request",
			ConstLabels: labels,
		}),
		TotalListenerNetworkRequest: promauto.NewCounter(prometheus.CounterOpts{
			Name:        "yuhaiin_listener_network_request_total",
			Help:        "The total number of listener network request",
			ConstLabels: labels,
		}),
		TotalListenerTransportRequest: promauto.NewCounter(prometheus.CounterOpts{
			Name:        "yuhaiin_listener_transport_request_total",
			Help:        "The total number of listener transport request",
			ConstLabels: labels,
		}),
		TotalHappyEyeballsv2DialRequest: promauto.NewCounter(prometheus.CounterOpts{
			Name:        "yuhaiin_happy_eyeballsv2_dial_request_total",
			Help:        "The total number of happy eyeballv2 dial request",
			ConstLabels: labels,
		}),
		HappyEyeballsv2IPsAttempted: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:        "yuhaiin_happy_eyeballsv2_ip_attempts",
			Help:        "The number of happy eyeballv2 ip attempts for each dial request",
			ConstLabels: labels,
			Buckets:     []float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 14, 18, 20},
		}),

		TotalConnection: promauto.NewCounter(prometheus.CounterOpts{
			Name:        "yuhaiin_connection_total",
			Help:        "The total number of connections",
			ConstLabels: labels,
		}),
		TotalGeoCountry: promauto.NewCounterVec(prometheus.CounterOpts{
			Name:        "yuhaiin_request_geo_country_total",
			Help:        "The total number of requests by country",
			ConstLabels: labels,
		}, []string{"country"}),
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
			Buckets:     []float64{50, 100, 200, 300, 400, 500, 600, 700, 800, 900, 1000, 1500, 2000, 2500, 3000, 5000, 10000},
			ConstLabels: labels,
		}),
		StreamConnectSummarySeconds: promauto.NewSummary(prometheus.SummaryOpts{
			Name:        "yuhaiin_stream_connect_summary_seconds",
			Help:        "The summary of tcp connect",
			ConstLabels: labels,
		}),
		DNSServerProcessTotal: promauto.NewCounter(prometheus.CounterOpts{
			Name:        "yuhaiin_dns_server_process_total",
			Help:        "The total number of dns process",
			ConstLabels: labels,
		}),
		LookupIPFailedTotal: promauto.NewCounterVec(prometheus.CounterOpts{
			Name:        "yuhaiin_dns_lookup_ip_failed_total",
			Help:        "The total number of dns lookup ip failed",
			ConstLabels: labels,
		}, []string{"rcode", "type"}),
		LookupIPTotal: promauto.NewCounterVec(prometheus.CounterOpts{
			Name:        "yuhaiin_dns_lookup_ip_total",
			Help:        "The total number of dns lookup ip",
			ConstLabels: labels,
		}, []string{"type"}),
		DNSQueryDurationSeconds: promauto.NewHistogramVec(prometheus.HistogramOpts{
			Name:        "yuhaiin_dns_query_duration_seconds",
			Help:        "The duration of dns query",
			Buckets:     []float64{50, 100, 200, 300, 400, 500, 600, 700, 800, 900, 1000, 1500, 2000, 2500, 3000, 5000, 10000},
			ConstLabels: labels,
		}, []string{"name"}),
		DNSQueryTotal: promauto.NewCounterVec(prometheus.CounterOpts{
			Name:        "yuhaiin_dns_query_total",
			Help:        "The total number of dns query",
			ConstLabels: labels,
		}, []string{"name"}),
		DNSQueryErrorTotal: promauto.NewCounterVec(prometheus.CounterOpts{
			Name:        "yuhaiin_dns_query_error_total",
			Help:        "The total number of dns query error",
			ConstLabels: labels,
		}, []string{"name"}),
		TCPDialFailedTotal: promauto.NewCounter(prometheus.CounterOpts{
			Name:        "yuhaiin_tcp_dial_failed_total",
			Help:        "The total number of tcp dial failed",
			ConstLabels: labels,
		}),

		FakeIPCacheHitTotal: promauto.NewCounter(prometheus.CounterOpts{
			Name:        "yuhaiin_fake_ip_cache_hit_total",
			Help:        "The total number of fake ip cache hit",
			ConstLabels: labels,
		}),
		FakeIPCacheMissTotal: promauto.NewCounter(prometheus.CounterOpts{
			Name:        "yuhaiin_fake_ip_cache_miss_total",
			Help:        "The total number of fake ip cache miss",
			ConstLabels: labels,
		}),

		TrieMatchDurationSeconds: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:        "yuhaiin_trie_match_duration_seconds",
			Help:        "The duration of trie match",
			Buckets:     []float64{5, 10, 20, 30, 40, 50, 100, 150, 200, 250, 300, 350, 400, 450, 500, 600, 1000},
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
	p.DNSServerProcessTotal.Inc()
}

func (p *Prometheus) AddLookupIPFailed(rcode string, t dns.Type) {
	p.LookupIPFailedTotal.WithLabelValues(rcode, t.String()).Inc()
}

func (p *Prometheus) AddLookupIP(t dns.Type) {
	p.LookupIPTotal.WithLabelValues(t.String()).Inc()
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

func (p *Prometheus) AddDnsQueryDuration(name string, t float64) {
	p.DNSQueryDurationSeconds.WithLabelValues(name).Observe(t)
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

func (p *Prometheus) AddTrieMatchDuration(t float64) {
	p.TrieMatchDurationSeconds.Observe(t)
}

func (p *Prometheus) AddGeoCountry(country string) {
	p.TotalGeoCountry.WithLabelValues(country).Inc()
}
