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

type Config struct {
	MSS, MaxWindow uint64
	InitialRTT     time.Duration
}
type SentPacket struct {
	Now                             time.Time
	Bytes, BytesInFlight, Delivered uint64
	AppLimited                      bool
}
type AckEvent struct {
	Now                                                                time.Time
	AckedBytes, BytesInFlight, Delivered, PriorDelivered, DeliveryRate uint64
	RTT                                                                time.Duration
	AppLimited, RecoveryDone, InRecovery                               bool
}
type LossEvent struct {
	Now                      time.Time
	BytesInFlight, LostBytes uint64
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
