package trafficcontrol

import (
	"errors"
	"fmt"
	"maps"
	"sync/atomic"
)

type Rate struct {
	BytesPerSecond int64 `json:"bytesPerSecond"`
	BurstBytes int64 `json:"burstBytes"`
}

type Profile struct {
	Upload Rate `json:"upload"`
	Download Rate `json:"download"`
}

// Config is a policy snapshot; rule IDs are taken from the existing router,
// not matched by a separate QoS rule engine. A bound profile is a shared
// group limit per inbound/rule identity, not a per-TCP-connection limit.
type Config struct {
	Enabled bool `json:"enabled"`
	Global Profile `json:"global"`
	DefaultProfile string `json:"defaultProfile,omitempty"`
	Profiles map[string]Profile `json:"profiles,omitempty"`
	InboundProfiles map[string]string `json:"inboundProfiles,omitempty"`
	RouteProfiles map[string]string `json:"routeProfiles,omitempty"`
}

type compiledPair struct {up,down *Limiter}

func compilePair(spec Profile) (compiledPair,error) {
	up,err:=NewLimiter(spec.Upload.BytesPerSecond,spec.Upload.BurstBytes)
	if err!=nil {return compiledPair{},fmt.Errorf("upload: %w",err)}
	down,err:=NewLimiter(spec.Download.BytesPerSecond,spec.Download.BurstBytes)
	if err!=nil {return compiledPair{},fmt.Errorf("download: %w",err)}
	return compiledPair{up:up,down:down},nil
}

type policySnapshot struct {
	config Config
	global, fallback compiledPair
	inbound,route map[string]compiledPair
}

type Manager struct {
	// An immutable snapshot replaces every configuration atomically; old
	// stream references retain their old shaper state to avoid resetting
	// debt or altering in-flight transport behavior.
	active atomic.Pointer[policySnapshot]
}

// NewManager starts with no default rate cap.
func NewManager() *Manager {
	m:=new(Manager)
	m.active.Store(&policySnapshot{})
	return m
}

func cloneConfig(c Config) Config {
	c.Profiles=maps.Clone(c.Profiles)
	c.InboundProfiles=maps.Clone(c.InboundProfiles)
	c.RouteProfiles=maps.Clone(c.RouteProfiles)
	return c
}

func (m *Manager) Config() Config {
	if m==nil{return Config{}}
	s:=m.active.Load()
	if s==nil{return Config{}}
	return cloneConfig(s.config)
}

func (m *Manager) Apply(c Config) error {
	if m==nil{return errors.New("trafficcontrol: nil manager")}
	c=cloneConfig(c)
	s:=&policySnapshot{config:c,inbound:make(map[string]compiledPair),route:make(map[string]compiledPair)}
	var err error
	s.global,err=compilePair(c.Global)
	if err!=nil{return fmt.Errorf("global: %w",err)}
	for id,p:=range c.Profiles {
		if id==""{return errors.New("trafficcontrol: empty profile ID")}
		if _,err=compilePair(p);err!=nil{return fmt.Errorf("profile %q: %w",id,err)}
	}
	profile:=func(id string)(Profile,error){
		p,ok:=c.Profiles[id]
		if !ok{return Profile{},fmt.Errorf("trafficcontrol: unknown profile %q",id)}
		return p,nil
	}
	if c.DefaultProfile!="" {
		p,e:=profile(c.DefaultProfile);if e!=nil{return e}
		s.fallback,err=compilePair(p);if err!=nil{return err}
	}
	for id,name:=range c.InboundProfiles {
		if id==""{return errors.New("trafficcontrol: empty inbound ID")}
		p,e:=profile(name);if e!=nil{return fmt.Errorf("inbound %q: %w",id,e)}
		s.inbound[id],err=compilePair(p);if err!=nil{return err}
	}
	for id,name:=range c.RouteProfiles {
		if id==""{return errors.New("trafficcontrol: empty route rule ID")}
		p,e:=profile(name);if e!=nil{return fmt.Errorf("rule %q: %w",id,e)}
		s.route[id],err=compilePair(p);if err!=nil{return err}
	}
	m.active.Store(s)
	return nil
}

func (m *Manager) Resolve(inboundID,routeID string) Policy {
	if m==nil{return Policy{}}
	s:=m.active.Load()
	if s==nil || !s.config.Enabled{return Policy{}}
	p:=Policy{}
	inbound,hasInbound:=s.inbound[inboundID]
	rule,hasRule:=s.route[routeID]
	// The fallback group applies only when neither identity is bound.
	base:=s.fallback
	if hasInbound||hasRule{base=compiledPair{}}
	p.up=[4]*Limiter{s.global.up,base.up,inbound.up,rule.up}
	p.down=[4]*Limiter{s.global.down,base.down,inbound.down,rule.down}
	return p
}
