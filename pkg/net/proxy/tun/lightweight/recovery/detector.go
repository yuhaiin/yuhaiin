// Package recovery implements per-connection TCP loss detection and probing.
// The transport owns packet storage, delivery accounting, timers and congestion
// control. Detectors consume borrowed metadata and return bounded decisions.
package recovery

import (
	"fmt"
	"slices"
	"sync"
	"time"
)

type Range struct{ Start, End uint32 }

type Segment struct {
	Range
	Sent                                   time.Time
	Transmissions                          int
	RetransmitEnd                          uint32
	SACKed, Lost, Repair, Data, PMTURepair bool
}

// Flight is sequence ordered. It is borrowed for a call, must not be retained,
// and never exposes packet buffers or permits changes to transport state.
type Flight interface {
	Len() int
	At(int) Segment
}

type Kind uint8

const (
	ACK Kind = iota
	Timer
	Timeout
	Reneging
	Transmit
)

type Event struct {
	Kind                                           Kind
	Now                                            time.Time
	Una, Next, MSS                                 uint32
	Acked                                          uint64
	DupACKs                                        int
	SRTT                                           time.Duration
	RTOAt                                          time.Time
	SACK, InRecovery, RecoveryDone, HasSACK, DSACK bool
	Duplicate                                      Range
	CanProbe                                       bool
}

// Decision never allocates a list proportional to flight size. More requests
// another evaluation after the transport applies this batch. Probe requests
// are distinct from proven loss, including loss already repaired by a probe.
type Decision struct {
	Losses              [64]Range
	Count               int
	More                bool
	Next                time.Time
	Probe, RepairedLoss bool
	RepairedBytes       uint32
}

func (d *Decision) lose(s Segment) {
	if d.Count == len(d.Losses) {
		d.More = true
		return
	}
	d.Losses[d.Count] = s.Range
	d.Count++
}

type SentEvent struct {
	Segment
	Next  uint32
	Probe bool
}

// Detector methods are serialized by the connection lock. Delivered is called
// once per newly delivered range, before its transport descriptor is released.
// Sent is called only after successful output admission, including probes.
type Detector interface {
	Sent(SentEvent)
	Delivered(Segment, time.Time)
	Evaluate(Event, Flight) Decision
}

type Factory func() Detector

var registry = struct {
	sync.RWMutex
	factories map[string]Factory
}{factories: map[string]Factory{
	"classic":  func() Detector { return &classic{} },
	"rack-tlp": func() Detector { return &rack{multiplier: 1} },
}}

func Register(name string, factory Factory) error {
	registry.Lock()
	defer registry.Unlock()
	if name == "" || factory == nil {
		return fmt.Errorf("recovery: invalid registration %q", name)
	}
	if _, ok := registry.factories[name]; ok {
		return fmt.Errorf("recovery: duplicate detector %q", name)
	}
	registry.factories[name] = factory
	return nil
}

func Names() []string {
	registry.RLock()
	defer registry.RUnlock()
	names := make([]string, 0, len(registry.factories))
	for name := range registry.factories {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

func New(name string) (Detector, error) {
	if name == "" {
		name = "classic"
	}
	registry.RLock()
	factory := registry.factories[name]
	registry.RUnlock()
	if factory == nil {
		return nil, fmt.Errorf("recovery: unknown detector %q", name)
	}
	d := factory()
	if d == nil {
		return nil, fmt.Errorf("recovery: nil detector %q", name)
	}
	return d, nil
}

func before(a, b uint32) bool { return int32(a-b) < 0 }
func after(a, b uint32) bool  { return before(b, a) }
func earlier(a, b time.Time) time.Time {
	if a.IsZero() || !b.IsZero() && b.Before(a) {
		return b
	}
	return a
}
