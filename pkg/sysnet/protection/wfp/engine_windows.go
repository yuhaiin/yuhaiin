//go:build windows

package wfp

import (
	"errors"
	"fmt"
	"slices"
	"sync"

	"github.com/tailscale/wf"
	"golang.org/x/sys/windows"
)

// Supported reports whether this platform has the WFP backend.
const Supported = true

// Fixed identities of Yuhaiin's WFP objects. Only objects with these IDs,
// and filters of this provider, are ever changed or deleted.
var (
	ProviderID = wf.ProviderID(windows.GUID{Data1: 0x7975_6861, Data2: 0x6969, Data3: 0x6e01, Data4: [8]byte{'k', 'i', 'l', 'l', 's', 'w', 0, 1}})
	SublayerID = wf.SublayerID(windows.GUID{Data1: 0x7975_6861, Data2: 0x6969, Data3: 0x6e02, Data4: [8]byte{'k', 'i', 'l', 'l', 's', 'w', 0, 2}})
)

// Engine holds two WFP sessions: a normal one for the baseline filters,
// which outlive the process, and a dynamic one for the runtime filters,
// which Windows deletes when the process exits.
type Engine struct {
	mu      sync.Mutex
	base    *wf.Session
	runtime *wf.Session
}

// Open connects to the filtering engine. It needs administrator rights.
func Open() (*Engine, error) {
	base, err := wf.New(&wf.Options{Name: "Yuhaiin Network Protection", Description: "Yuhaiin kill switch baseline"})
	if err != nil {
		return nil, fmt.Errorf("open the Windows Filtering Platform: %w", err)
	}
	return &Engine{base: base}, nil
}

// Close closes the sessions. The runtime filters disappear with the
// dynamic session; the baseline stays.
func (e *Engine) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	var err error
	if e.runtime != nil {
		err = e.runtime.Close()
		e.runtime = nil
	}
	if e.base != nil {
		err = errors.Join(err, e.base.Close())
		e.base = nil
	}
	return err
}

func (e *Engine) runtimeSession() (*wf.Session, error) {
	if e.runtime != nil {
		return e.runtime, nil
	}
	s, err := wf.New(&wf.Options{Name: "Yuhaiin Network Protection (runtime)", Description: "Permits that end with the Yuhaiin process", Dynamic: true})
	if err != nil {
		return nil, err
	}
	e.runtime = s
	return s, nil
}

func (e *Engine) ensureObjects() error {
	providers, err := e.base.Providers()
	if err != nil {
		return err
	}
	if !slices.ContainsFunc(providers, func(p *wf.Provider) bool { return p.ID == ProviderID }) {
		if err := e.base.AddProvider(&wf.Provider{ID: ProviderID, Name: "Yuhaiin", Description: "Yuhaiin Network Protection (kill switch)", Persistent: true}); err != nil {
			return fmt.Errorf("add the Yuhaiin provider: %w", err)
		}
	}
	sublayers, err := e.base.Sublayers(ProviderID)
	if err != nil {
		return err
	}
	if !slices.ContainsFunc(sublayers, func(s *wf.Sublayer) bool { return s.ID == SublayerID }) {
		if err := e.base.AddSublayer(&wf.Sublayer{ID: SublayerID, Name: "Yuhaiin kill switch", Description: "Blocks Internet traffic outside Yuhaiin",
			Persistent: true, Provider: ProviderID, Weight: 0xffff}); err != nil {
			return fmt.Errorf("add the Yuhaiin sublayer: %w", err)
		}
	}
	return nil
}

func matches(f Filter) []*wf.Match {
	var out []*wf.Match
	for _, c := range f.Conditions {
		switch c.Kind {
		case "loopback":
			out = append(out, &wf.Match{Field: wf.FieldFlags, Op: wf.MatchTypeFlagsAllSet, Value: wf.ConditionFlagIsLoopback})
		case "remote":
			out = append(out, &wf.Match{Field: wf.FieldIPRemoteAddress, Op: wf.MatchTypeEqual, Value: c.Prefix})
		case "udp":
			out = append(out,
				&wf.Match{Field: wf.FieldIPProtocol, Op: wf.MatchTypeEqual, Value: wf.IPProtoUDP},
				&wf.Match{Field: wf.FieldIPLocalPort, Op: wf.MatchTypeEqual, Value: c.Local},
				&wf.Match{Field: wf.FieldIPRemotePort, Op: wf.MatchTypeEqual, Value: c.Remote})
		case "icmp6":
			// WFP stores the ICMP type in the local port field.
			out = append(out,
				&wf.Match{Field: wf.FieldIPProtocol, Op: wf.MatchTypeEqual, Value: wf.IPProtoICMPV6},
				&wf.Match{Field: wf.FieldIPLocalPort, Op: wf.MatchTypeEqual, Value: c.Local})
		case "app":
			out = append(out, &wf.Match{Field: wf.FieldALEAppID, Op: wf.MatchTypeEqual, Value: c.App})
		case "interface":
			out = append(out, &wf.Match{Field: wf.FieldIPLocalInterface, Op: wf.MatchTypeEqual, Value: c.LUID})
		}
	}
	return out
}

func toRule(f Filter) (*wf.Rule, error) {
	layer := wf.LayerALEAuthConnectV4
	if f.V6 {
		layer = wf.LayerALEAuthConnectV6
	}
	action := wf.ActionBlock
	if f.Permit {
		action = wf.ActionPermit
	}
	conds := matches(f)
	for _, c := range f.Conditions {
		if c.Kind == "app" {
			id, err := wf.AppID(c.App)
			if err != nil {
				return nil, fmt.Errorf("application id of %s: %w", c.App, err)
			}
			for _, m := range conds {
				if m.Field == wf.FieldALEAppID {
					m.Value = id
				}
			}
		}
	}
	return &wf.Rule{ID: wf.RuleID(windows.GUID(guidOf(f.GUID()))), Name: "Yuhaiin kill switch: " + f.String(), Description: f.Label,
		Layer: layer, Sublayer: SublayerID, Provider: ProviderID, Weight: f.Weight, Conditions: conds, Action: action, Persistent: f.Persistent}, nil
}

func guidOf(b [16]byte) windows.GUID {
	return windows.GUID{Data1: uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3]), Data2: uint16(b[4])<<8 | uint16(b[5]),
		Data3: uint16(b[6])<<8 | uint16(b[7]), Data4: [8]byte(b[8:16])}
}

// Ours lists the filters of Yuhaiin's provider.
func (e *Engine) Ours() ([]*wf.Rule, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.oursLocked()
}

func (e *Engine) oursLocked() ([]*wf.Rule, error) {
	rules, err := e.base.Rules()
	if err != nil {
		return nil, err
	}
	var out []*wf.Rule
	for _, r := range rules {
		if r.Provider == ProviderID {
			out = append(out, r)
		}
	}
	return out, nil
}

// Apply makes Yuhaiin's filters exactly plan: new filters are added before
// obsolete ones are deleted, and the block filters never go away, so an
// update never opens the network.
func (e *Engine) Apply(plan Plan) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.ensureObjects(); err != nil {
		return err
	}
	existing, err := e.oursLocked()
	if err != nil {
		return err
	}
	have := map[wf.RuleID]bool{}
	for _, r := range existing {
		have[r.ID] = true
	}
	want := map[wf.RuleID]bool{}
	for _, f := range plan.Filters {
		r, err := toRule(f)
		if err != nil {
			return err
		}
		want[r.ID] = true
		if have[r.ID] {
			continue
		}
		s := e.base
		if f.Runtime {
			if s, err = e.runtimeSession(); err != nil {
				return err
			}
		}
		if err := s.AddRule(r); err != nil {
			return fmt.Errorf("add filter %q: %w", r.Name, err)
		}
	}
	var errs []error
	for _, r := range existing {
		if !want[r.ID] {
			if err := e.deleteLocked(r.ID); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

func (e *Engine) deleteLocked(id wf.RuleID) error {
	err := e.base.DeleteRule(id)
	if err != nil && e.runtime != nil {
		err = e.runtime.DeleteRule(id)
	}
	return err
}

// Remove deletes every filter of Yuhaiin's provider, its sublayer and the
// provider. Other providers are not touched.
func (e *Engine) Remove() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.runtime != nil {
		_ = e.runtime.Close()
		e.runtime = nil
	}
	existing, err := e.oursLocked()
	if err != nil {
		return err
	}
	var errs []error
	for _, r := range existing {
		if err := e.base.DeleteRule(r.ID); err != nil {
			errs = append(errs, err)
		}
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}
	if sublayers, err := e.base.Sublayers(ProviderID); err == nil && slices.ContainsFunc(sublayers, func(s *wf.Sublayer) bool { return s.ID == SublayerID }) {
		if err := e.base.DeleteSublayer(SublayerID); err != nil {
			return err
		}
	}
	if providers, err := e.base.Providers(); err == nil && slices.ContainsFunc(providers, func(p *wf.Provider) bool { return p.ID == ProviderID }) {
		return e.base.DeleteProvider(ProviderID)
	}
	return nil
}

// Sublayers lists every sublayer of the system with its weight, for the
// rules view (higher weights are evaluated first).
func (e *Engine) Sublayers() ([]*wf.Sublayer, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.base.Sublayers()
}
