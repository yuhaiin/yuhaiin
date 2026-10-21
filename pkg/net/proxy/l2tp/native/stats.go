package native

import "sync/atomic"

// SessionStats identifies where L2TP datagrams disappear. All values are
// cumulative for one session and safe to read while the session is running.
type SessionStats struct {
	ReceivedDatagrams uint64 `json:"received_datagrams"`
	SentDatagrams     uint64 `json:"sent_datagrams"`
	DecodeErrors      uint64 `json:"decode_errors"`
	WrongVersion      uint64 `json:"wrong_version"`
	WrongSession      uint64 `json:"wrong_session"`
	InvalidPayload    uint64 `json:"invalid_payload"`
	InvalidPPP        uint64 `json:"invalid_ppp"`
	InvalidIP         uint64 `json:"invalid_ip"`
	PPPQueueDrops     uint64 `json:"ppp_queue_drops"`
	FrameQueueDrops   uint64 `json:"frame_queue_drops"`
	FramesAccepted    uint64 `json:"frames_accepted"`
}

type sessionCounters struct {
	receivedDatagrams atomic.Uint64
	sentDatagrams     atomic.Uint64
	decodeErrors      atomic.Uint64
	wrongVersion      atomic.Uint64
	wrongSession      atomic.Uint64
	invalidPayload    atomic.Uint64
	invalidPPP        atomic.Uint64
	invalidIP         atomic.Uint64
	pppQueueDrops     atomic.Uint64
	frameQueueDrops   atomic.Uint64
	framesAccepted    atomic.Uint64
}

func (s *Session) Stats() SessionStats {
	return SessionStats{
		ReceivedDatagrams: s.stats.receivedDatagrams.Load(),
		SentDatagrams:     s.stats.sentDatagrams.Load(),
		DecodeErrors:      s.stats.decodeErrors.Load(),
		WrongVersion:      s.stats.wrongVersion.Load(),
		WrongSession:      s.stats.wrongSession.Load(),
		InvalidPayload:    s.stats.invalidPayload.Load(),
		InvalidPPP:        s.stats.invalidPPP.Load(),
		InvalidIP:         s.stats.invalidIP.Load(),
		PPPQueueDrops:     s.stats.pppQueueDrops.Load(),
		FrameQueueDrops:   s.stats.frameQueueDrops.Load(),
		FramesAccepted:    s.stats.framesAccepted.Load(),
	}
}
