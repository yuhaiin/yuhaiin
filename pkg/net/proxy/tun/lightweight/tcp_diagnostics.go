package lightweight

import (
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/lightweight/congestion"
)

// TCPDiagnostics is a point-in-time view of an active TCP flow. This does not
// include application payloads or mutable protocol buffers.
type TCPDiagnostics struct {
	State             TCPState               `json:"state"`
	Local             string                 `json:"local"`
	Remote            string                 `json:"remote"`
	SndUna            uint32                 `json:"snd_una"`
	SndNxt            uint32                 `json:"snd_nxt"`
	SndEnd            uint32                 `json:"snd_end"`
	RcvNxt            uint32                 `json:"rcv_nxt"`
	RcvAdv            uint32                 `json:"rcv_adv"`
	PeerWindow        uint32                 `json:"peer_window"`
	ReceiveWindow     uint32                 `json:"receive_window"`
	BytesInFlight     uint64                 `json:"bytes_in_flight"`
	SendQueueBytes    int                    `json:"send_queue_bytes"`
	ReceiveQueueBytes int                    `json:"receive_queue_bytes"`
	OutOfOrderPieces  int                    `json:"out_of_order_pieces"`
	CongestionWindow  uint64                 `json:"cwnd_bytes"`
	PacingRate        uint64                 `json:"pacing_bytes_per_second"`
	SRTTMilliseconds  float64                `json:"srtt_ms"`
	RTOMilliseconds   float64                `json:"rto_ms"`
	RTODueInMS        float64                `json:"rto_due_in_ms"`
	PacingDueInMS     float64                `json:"pacing_due_in_ms"`
	PersistDueInMS    float64                `json:"persist_due_in_ms"`
	Retries           int                    `json:"retries"`
	DuplicateACKs     int                    `json:"duplicate_acks"`
	Recovering        bool                   `json:"recovering"`
	RepairPending     bool                   `json:"repair_pending"`
	LostBytes         uint64                 `json:"lost_bytes"`
	OutputWaiting     bool                   `json:"output_waiting"`
	BBR               *congestion.BBRSnapshot `json:"bbr,omitempty"`
}

// DiagnosticSnapshot can be called from a test after a deadline or while the
// connection is active. Scheduling and connection state share c.mu.
func (c *TCPConn) DiagnosticSnapshot() TCPDiagnostics {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	until := func(at time.Time) float64 {
		if at.IsZero() {
			return 0
		}
		return float64(at.Sub(now)) / float64(time.Millisecond)
	}
	d := TCPDiagnostics{
		State: c.state,
		Local: c.key.local.String(), Remote: c.key.remote.String(),
		SndUna: c.sndUna, SndNxt: c.sndNxt, SndEnd: c.sndEnd,
		RcvNxt: c.rcvNxt, RcvAdv: c.rcvAdv,
		PeerWindow: c.peerWindow, ReceiveWindow: c.receiveWindow(),
		BytesInFlight: c.flight(), SendQueueBytes: c.txBytes,
		ReceiveQueueBytes: c.rxBytes, OutOfOrderPieces: len(c.ooo),
		CongestionWindow: c.controller.CongestionWindow(),
		PacingRate: c.controller.PacingRate(),
		SRTTMilliseconds: float64(c.srtt)/float64(time.Millisecond),
		RTOMilliseconds: float64(c.rto)/float64(time.Millisecond),
		RTODueInMS: until(c.rtoAt), PacingDueInMS: until(c.paceAt),
		PersistDueInMS: until(c.persistAt),
		Retries: c.retries, DuplicateACKs: c.dupACKs,
		Recovering: c.recovering, RepairPending: c.repairPending,
		LostBytes: c.lost, OutputWaiting: c.outputWaiting,
	}
	if bbr, ok := c.controller.(interface{ Snapshot() congestion.BBRSnapshot }); ok {
		b := bbr.Snapshot()
		d.BBR = &b
	}
	return d
}
