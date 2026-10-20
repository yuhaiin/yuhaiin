package node

import (
	"context"
	"database/sql"
	"encoding/json/v2"
	"maps"
	"net"
	"reflect"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

const nodeMetricsInterval = 5 * time.Second
const recentNodeObservation = 2 * time.Minute

// nodeTotals are persisted separately from ephemeral active connection counts.
type nodeTotals struct {
	UploadBytes    uint64                          `json:"uploadBytes"`
	DownloadBytes  uint64                          `json:"downloadBytes"`
	UDPSentPackets uint64                          `json:"udpSentPackets"`
	UDPRecvPackets uint64                          `json:"udpRecvPackets"`
	TCPAttempts    uint64                          `json:"tcpAttempts"`
	TCPConnections uint64                          `json:"tcpConnections"`
	UDPAttempts    uint64                          `json:"udpAttempts"`
	UDPSessions    uint64                          `json:"udpSessions"`
	PingAttempts   uint64                          `json:"pingAttempts"`
	Failures       uint64                          `json:"failures"`
	LastSuccessAt  int64                           `json:"lastSuccessAt"`
	LastFailureAt  int64                           `json:"lastFailureAt"`
	LastUsedAt     int64                           `json:"lastUsedAt"`
	LastError      string                          `json:"lastError,omitempty"`
	Probes         map[string]contract.ProbeStatus `json:"probes,omitempty"`
}

type nodeCounters struct {
	upload, download, udpSent, udpReceived               atomic.Uint64
	tcpAttempts, tcpConnected, udpAttempts, udpConnected atomic.Uint64
	pingAttempts, failures                               atomic.Uint64
	activeTCP, activeUDP                                 atomic.Int64
	uploadBps, downloadBps                               atomic.Uint64
	lastSuccess, lastFailure, lastUsed                   atomic.Int64
	mu                                                   sync.Mutex
	lastError                                            string
	probes                                               map[string]contract.ProbeStatus
}

func (n *nodeCounters) snapshot() nodeTotals {
	v := nodeTotals{
		UploadBytes: n.upload.Load(), DownloadBytes: n.download.Load(),
		UDPSentPackets: n.udpSent.Load(), UDPRecvPackets: n.udpReceived.Load(),
		TCPAttempts: n.tcpAttempts.Load(), TCPConnections: n.tcpConnected.Load(),
		UDPAttempts: n.udpAttempts.Load(), UDPSessions: n.udpConnected.Load(),
		PingAttempts: n.pingAttempts.Load(), Failures: n.failures.Load(),
		LastSuccessAt: n.lastSuccess.Load(), LastFailureAt: n.lastFailure.Load(),
		LastUsedAt: n.lastUsed.Load(),
	}
	n.mu.Lock()
	v.lastErrorAndProbes(n)
	n.mu.Unlock()
	return v
}

func (v *nodeTotals) lastErrorAndProbes(n *nodeCounters) {
	v.LastError = n.lastError
	v.Probes = maps.Clone(n.probes)
}

func (n *nodeCounters) restore(v nodeTotals) {
	n.upload.Store(v.UploadBytes)
	n.download.Store(v.DownloadBytes)
	n.udpSent.Store(v.UDPSentPackets)
	n.udpReceived.Store(v.UDPRecvPackets)
	n.tcpAttempts.Store(v.TCPAttempts)
	n.tcpConnected.Store(v.TCPConnections)
	n.udpAttempts.Store(v.UDPAttempts)
	n.udpConnected.Store(v.UDPSessions)
	n.pingAttempts.Store(v.PingAttempts)
	n.failures.Store(v.Failures)
	n.lastSuccess.Store(v.LastSuccessAt)
	n.lastFailure.Store(v.LastFailureAt)
	n.lastUsed.Store(v.LastUsedAt)
	n.mu.Lock()
	n.lastError = v.LastError
	n.probes = maps.Clone(v.Probes)
	n.mu.Unlock()
}

func (n *nodeCounters) success() {
	now := time.Now().UnixNano()
	n.lastSuccess.Store(now)
	n.lastUsed.Store(now)
}

func (n *nodeCounters) failure(err error) {
	if err == nil {
		return
	}
	now := time.Now().UnixNano()
	n.failures.Add(1)
	n.lastFailure.Store(now)
	n.lastUsed.Store(now)
	msg := err.Error()
	if len(msg) > 512 {
		msg = msg[:512]
	}
	n.mu.Lock()
	n.lastError = msg
	n.mu.Unlock()
}

func (n *nodeCounters) probe(kind string, result contract.LatencyResponse, err error) {
	if kind == "" {
		kind = "tcp"
	}
	if err != nil {
		result.OK = false
		result.Error = err.Error()
	}
	if !result.OK && result.Error == "" {
		result.Error = "probe did not succeed"
	}
	if len(result.Error) > 512 {
		result.Error = result.Error[:512]
	}
	n.mu.Lock()
	if n.probes == nil {
		n.probes = make(map[string]contract.ProbeStatus)
	}
	n.probes[kind] = contract.ProbeStatus{CheckedAt: time.Now().Unix(), Result: result}
	if !result.OK {
		n.lastError = result.Error
	}
	n.mu.Unlock()
	if !result.OK {
		n.lastFailure.Store(time.Now().UnixNano())
	} else {
		n.success()
	}
}

func (n *nodeCounters) status(id string) contract.RuntimeStatus {
	v := n.snapshot()
	state := "unknown"
	now := time.Now().UnixNano()
	if v.LastFailureAt > v.LastSuccessAt && now-v.LastFailureAt <= recentNodeObservation.Nanoseconds() {
		state = "degraded"
	} else if v.LastSuccessAt > 0 && v.LastSuccessAt >= v.LastFailureAt && now-v.LastSuccessAt <= recentNodeObservation.Nanoseconds() {
		state = "healthy"
	}
	return contract.RuntimeStatus{
		ID: id, State: state, UploadBytes: strconv.FormatUint(v.UploadBytes, 10),
		DownloadBytes:  strconv.FormatUint(v.DownloadBytes, 10),
		UploadBps:      strconv.FormatUint(n.uploadBps.Load(), 10),
		DownloadBps:    strconv.FormatUint(n.downloadBps.Load(), 10),
		UDPSentPackets: strconv.FormatUint(v.UDPSentPackets, 10),
		UDPRecvPackets: strconv.FormatUint(v.UDPRecvPackets, 10),
		TCPAttempts:    strconv.FormatUint(v.TCPAttempts, 10),
		TCPConnections: strconv.FormatUint(v.TCPConnections, 10),
		UDPAttempts:    strconv.FormatUint(v.UDPAttempts, 10),
		UDPSessions:    strconv.FormatUint(v.UDPSessions, 10),
		PingAttempts:   strconv.FormatUint(v.PingAttempts, 10),
		Failures:       strconv.FormatUint(v.Failures, 10),
		ActiveTCP:      n.activeTCP.Load(), ActiveUDP: n.activeUDP.Load(),
		LastSuccessAt: v.LastSuccessAt / int64(time.Second), LastFailureAt: v.LastFailureAt / int64(time.Second),
		LastUsedAt: v.LastUsedAt / int64(time.Second), LastError: v.LastError, Probes: v.Probes,
	}
}

// nodeObserver serializes database flushes with deletes, but never holds this
// lock in a packet or stream Read/Write operation.
type nodeObserver struct {
	db         *sql.DB
	mu         sync.Mutex
	nodes      map[string]*nodeCounters
	saved      map[string]nodeTotals
	lastRates  map[string][2]uint64
	lastSample time.Time
	stop       chan struct{}
	done       chan struct{}
}

func newNodeObserver(ctx context.Context, db *sql.DB) (*nodeObserver, error) {
	o := &nodeObserver{db: db, nodes: make(map[string]*nodeCounters), saved: make(map[string]nodeTotals), lastRates: make(map[string][2]uint64), lastSample: time.Now(), stop: make(chan struct{}), done: make(chan struct{})}
	rows, err := db.QueryContext(ctx, `SELECT node_id, data_json FROM node_runtime_stats`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id, raw string
		if err = rows.Scan(&id, &raw); err != nil {
			break
		}
		var v nodeTotals
		if err = json.Unmarshal([]byte(raw), &v); err != nil {
			break
		}
		n := new(nodeCounters)
		n.restore(v)
		o.nodes[id] = n
		o.saved[id] = v
		o.lastRates[id] = [2]uint64{v.UploadBytes, v.DownloadBytes}
	}
	if err == nil {
		err = rows.Err()
	}
	_ = rows.Close()
	if err != nil {
		return nil, err
	}
	go o.run()
	return o, nil
}

func (o *nodeObserver) run() {
	defer close(o.done)
	ticker := time.NewTicker(nodeMetricsInterval)
	defer ticker.Stop()
	for {
		select {
		case <-o.stop:
			return
		case <-ticker.C:
			if err := o.flush(context.Background()); err != nil {
				log.Warn("persist outbound observability failed", "err", err)
			}
		}
	}
}

func (o *nodeObserver) counter(id string) *nodeCounters {
	o.mu.Lock()
	defer o.mu.Unlock()
	if n := o.nodes[id]; n != nil {
		return n
	}
	n := new(nodeCounters)
	o.nodes[id] = n
	return n
}

func (o *nodeObserver) status(id string) contract.RuntimeStatus {
	o.mu.Lock()
	n := o.nodes[id]
	o.mu.Unlock()
	if n == nil {
		return contract.RuntimeStatus{ID: id, State: "unknown", UploadBytes: "0", DownloadBytes: "0", UploadBps: "0", DownloadBps: "0", UDPSentPackets: "0", UDPRecvPackets: "0", TCPAttempts: "0", TCPConnections: "0", UDPAttempts: "0", UDPSessions: "0", PingAttempts: "0", Failures: "0"}
	}
	return n.status(id)
}

func (o *nodeObserver) flush(ctx context.Context) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.flushLocked(ctx)
}
func (o *nodeObserver) flushLocked(ctx context.Context) error {
	if o.db == nil {
		return nil
	}
	changed := make(map[string]nodeTotals)
	nowSample := time.Now()
	elapsed := nowSample.Sub(o.lastSample).Seconds()
	if elapsed <= 0 {
		elapsed = 1
	}
	o.lastSample = nowSample
	for id, n := range o.nodes {
		v := n.snapshot()
		last := o.lastRates[id]
		if v.UploadBytes >= last[0] {
			n.uploadBps.Store(uint64(float64(v.UploadBytes-last[0]) / elapsed))
		}
		if v.DownloadBytes >= last[1] {
			n.downloadBps.Store(uint64(float64(v.DownloadBytes-last[1]) / elapsed))
		}
		o.lastRates[id] = [2]uint64{v.UploadBytes, v.DownloadBytes}
		if saved, ok := o.saved[id]; !ok || !reflect.DeepEqual(saved, v) {
			changed[id] = v
		}
	}
	if len(changed) == 0 {
		return nil
	}
	tx, err := o.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO node_runtime_stats(node_id,data_json,updated_at)
		SELECT ?,?,? WHERE EXISTS(SELECT 1 FROM nodes_v2 WHERE id=?)
		ON CONFLICT(node_id) DO UPDATE SET data_json=excluded.data_json,updated_at=excluded.updated_at`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	now := time.Now().Unix()
	for id, v := range changed {
		b, er := json.Marshal(v)
		if er != nil {
			return er
		}
		if _, er = stmt.ExecContext(ctx, id, string(b), now, id); er != nil {
			return er
		}
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	maps.Copy(o.saved, changed)
	return nil
}

func (o *nodeObserver) delete(ctx context.Context, id string, fn func() error) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if err := fn(); err != nil {
		return err
	}
	delete(o.nodes, id)
	delete(o.saved, id)
	delete(o.lastRates, id)
	return nil
}
func (o *nodeObserver) prune(ctx context.Context, existing map[string]bool) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	for id := range o.nodes {
		if !existing[id] {
			delete(o.nodes, id)
			delete(o.saved, id)
			delete(o.lastRates, id)
		}
	}
	_, err := o.db.ExecContext(ctx, `DELETE FROM node_runtime_stats WHERE node_id NOT IN(SELECT id FROM nodes_v2)`)
	return err
}
func (o *nodeObserver) close() error {
	close(o.stop)
	<-o.done
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return o.flush(ctx)
}

// observedProxy measures logical payload at the requested node boundary.
// A nested Set records both logical use and underlying hop use. These are
// separate per-node views and must never be summed into global traffic.
type observedProxy struct {
	netapi.Proxy
	c *nodeCounters
}

func (p *observedProxy) Conn(ctx context.Context, a netapi.Address) (net.Conn, error) {
	p.c.tcpAttempts.Add(1)
	p.c.lastUsed.Store(time.Now().UnixNano())
	conn, err := p.Proxy.Conn(ctx, a)
	if err != nil {
		p.c.failure(err)
		return nil, err
	}
	p.c.tcpConnected.Add(1)
	p.c.activeTCP.Add(1)
	p.c.success()
	w := &observedConn{Conn: conn, c: p.c}
	if b, ok := conn.(netapi.BufferReader); ok {
		return &observedBufferedConn{observedConn: w, reader: b}, nil
	}
	return w, nil
}
func (p *observedProxy) PacketConn(ctx context.Context, a netapi.Address) (net.PacketConn, error) {
	p.c.udpAttempts.Add(1)
	p.c.lastUsed.Store(time.Now().UnixNano())
	conn, err := p.Proxy.PacketConn(ctx, a)
	if err != nil {
		p.c.failure(err)
		return nil, err
	}
	p.c.udpConnected.Add(1)
	p.c.activeUDP.Add(1)
	p.c.success()
	return &observedPacketConn{PacketConn: conn, c: p.c}, nil
}
func (p *observedProxy) Ping(ctx context.Context, a netapi.Address) (uint64, error) {
	p.c.pingAttempts.Add(1)
	v, err := p.Proxy.Ping(ctx, a)
	if err != nil {
		p.c.failure(err)
	} else {
		p.c.success()
	}
	return v, err
}

type observedConn struct {
	net.Conn
	c    *nodeCounters
	once sync.Once
}

func (c *observedConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.c.download.Add(uint64(n))
	}
	return n, err
}
func (c *observedConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 {
		c.c.upload.Add(uint64(n))
	}
	return n, err
}
func (c *observedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { c.c.activeTCP.Add(-1) })
	return err
}

type observedBufferedConn struct {
	*observedConn
	reader netapi.BufferReader
}

func (c *observedBufferedConn) ReadWithBuffer(f func() []byte) ([]byte, error) {
	b, err := c.reader.ReadWithBuffer(f)
	if len(b) > 0 {
		c.c.download.Add(uint64(len(b)))
	}
	return b, err
}

type observedPacketConn struct {
	net.PacketConn
	c    *nodeCounters
	once sync.Once
}

func (c *observedPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, a, err := c.PacketConn.ReadFrom(b)
	if n > 0 {
		c.c.download.Add(uint64(n))
		c.c.udpReceived.Add(1)
	}
	return n, a, err
}
func (c *observedPacketConn) WriteTo(b []byte, a net.Addr) (int, error) {
	n, err := c.PacketConn.WriteTo(b, a)
	if n > 0 {
		c.c.upload.Add(uint64(n))
		c.c.udpSent.Add(1)
	}
	return n, err
}
func (c *observedPacketConn) Close() error {
	err := c.PacketConn.Close()
	c.once.Do(func() { c.c.activeUDP.Add(-1) })
	return err
}

var _ net.Conn = (*observedConn)(nil)
var _ net.PacketConn = (*observedPacketConn)(nil)
var _ netapi.BufferReader = (*observedBufferedConn)(nil)
