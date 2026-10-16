// Package congestion implements per-connection congestion controllers.
// All sizes/windows are bytes, rates bytes/second, and times monotonic Go times.
// Controllers are called serially under their owning connection's lock.
package congestion

import (
	"errors"
	"fmt"
	"reflect"
	"sync"
	"time"
)

const DefaultPacingQuantum = time.Millisecond
const DefaultMaxBurstPackets = 64

type Config struct {
	MSS, MaxWindow uint64
	InitialRTT     time.Duration
	// Actual sender scheduling/batching bounds, independent of NIC offload.
	PacingQuantum   time.Duration
	MaxBurstPackets uint64
}
type SentPacket struct {
	Now                             time.Time
	Bytes, BytesInFlight, Delivered uint64
	AppLimited                      bool
	IdleRestart, Retransmission     bool
}
type AckEvent struct {
	Now                                                                time.Time
	AckedBytes, BytesInFlight, Delivered, PriorDelivered, DeliveryRate uint64
	// NewlyDelivered includes fresh SACK delivery; AckedBytes remains the
	// cumulative-ACK advance used by loss-based controllers. SampleDelivered,
	// SampleLost and TxInFlight describe the sampled transmission's flight.
	NewlyDelivered, SampleDelivered, SampleLost, TxInFlight, LostBytes uint64
	PriorInFlight                                                      uint64
	RateSample                                                         bool
	ACK, NextSeq                                                       uint32
	CwndLimited                                                        bool
	PacingDelay                                                        time.Duration
	RTT                                                                time.Duration
	AppLimited, RecoveryDone, InRecovery                               bool
}
type LossEvent struct {
	Now                               time.Time
	BytesInFlight, LostBytes          uint64
	Delivered, SampleLost, TxInFlight uint64
	AppLimited                        bool
}
type TimeoutEvent struct {
	Now           time.Time
	BytesInFlight uint64
}

type Controller interface {
	OnPacketSent(SentPacket)
	OnAck(AckEvent)
	OnLoss(LossEvent)
	OnTimeout(TimeoutEvent)
	CongestionWindow() uint64
	PacingRate() uint64
}

// LossSampler receives each inferred lost transmission, separately from the
// recovery-episode OnLoss/OnTimeout events. PMTU replacements are not losses.
// A controller may implement this without changing legacy recovery semantics.
type LossSampler interface{ OnPacketLost(LossEvent) }

// RateSampleLimiter marks deliberate model measurement dips so their lower
// delivery rates do not replace a bottleneck-bandwidth estimate.
type RateSampleLimiter interface{ RateSampleLimited() bool }

// MSSUpdater preserves a controller's byte model when PMTU changes the
// transport's segmentation size. Updating MSS does not reset congestion state.
type MSSUpdater interface{ UpdateMSS(uint64) }

type Factory func(Config) Controller

var registry = struct {
	sync.RWMutex
	factories map[string]Factory
}{factories: map[string]Factory{
	"reno":  func(c Config) Controller { return newReno(c) },
	"cubic": func(c Config) Controller { return newCubic(c) },
	"bbr":   func(c Config) Controller { return newBBR(c) },
}}

// Register adds a factory for future connections. Factories must return a new
// independent controller on every call. Existing connections are never changed.
func Register(name string, f Factory) error {
	if name == "" || f == nil {
		return errors.New("congestion: empty name or nil factory")
	}
	registry.Lock()
	defer registry.Unlock()
	if _, ok := registry.factories[name]; ok {
		return fmt.Errorf("congestion: %q already registered", name)
	}
	registry.factories[name] = f
	return nil
}
func New(name string, c Config) (Controller, error) {
	if name == "" {
		name = "cubic"
	}
	if c.MSS < 64 || c.MSS > 65535 {
		return nil, errors.New("congestion: MSS must be 64..65535 bytes")
	}
	if c.MaxWindow == 0 {
		c.MaxWindow = 16 << 20
	}
	if c.MaxWindow < 2*c.MSS || c.MaxWindow > 1<<30 {
		return nil, errors.New("congestion: invalid maximum window")
	}
	if c.InitialRTT == 0 {
		c.InitialRTT = 100 * time.Millisecond
	}
	if c.InitialRTT < 0 {
		return nil, errors.New("congestion: negative RTT")
	}
	if c.PacingQuantum == 0 {
		c.PacingQuantum = DefaultPacingQuantum
	}
	if c.MaxBurstPackets == 0 {
		c.MaxBurstPackets = DefaultMaxBurstPackets
	}
	if c.PacingQuantum < 0 || c.PacingQuantum > time.Second || c.MaxBurstPackets > 1024 {
		return nil, errors.New("congestion: invalid sender scheduling budget")
	}
	registry.RLock()
	f, ok := registry.factories[name]
	registry.RUnlock()
	if !ok {
		return nil, fmt.Errorf("congestion: unknown algorithm %q", name)
	}
	x := f(c)
	if x == nil || reflect.ValueOf(x).Kind() == reflect.Pointer && reflect.ValueOf(x).IsNil() {
		return nil, errors.New("congestion: factory returned nil")
	}
	if x.CongestionWindow() < c.MSS || x.CongestionWindow() > c.MaxWindow {
		return nil, errors.New("congestion: invalid initial window")
	}
	return x, nil
}
func initialWindow(c Config) uint64 { return min(c.MaxWindow, min(10*c.MSS, max(2*c.MSS, 14600))) }
