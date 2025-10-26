package netapi

import (
	"context"
	"errors"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/trie/maxminddb"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
)

type PacketSniffer interface {
	Packet(*Context, []byte)
}

type ResolverMode int

const (
	ResolverModeNoSpecified ResolverMode = iota
	ResolverModePreferIPv6
	ResolverModePreferIPv4
)

type ResolverOptions struct {
	isResolver              bool
	resolver                Resolver
	mode                    ResolverMode
	udpSkipResolveTarget    bool
	useFakeIP               bool
	fakeIPSkipCheckUpstream bool
}

func (r *ResolverOptions) SetResolver(resolver Resolver) *ResolverOptions {
	if r.isResolver && r.resolver != nil {
		return r
	}

	r.resolver = resolver
	return r
}

func (r *ResolverOptions) Resolver() Resolver {
	if r.resolver != nil {
		return r.resolver
	}

	return nil
}

func (r *ResolverOptions) IsResolver() bool {
	return r.isResolver
}

func (r *ResolverOptions) SetIsResolver() *ResolverOptions {
	r.isResolver = true
	return r
}

func (r *ResolverOptions) SetMode(mode ResolverMode) *ResolverOptions {
	r.mode = mode
	return r
}

func (r *ResolverOptions) Mode() ResolverMode {
	return r.mode
}

func (r *ResolverOptions) SetUdpSkipResolveTarget(skip bool) *ResolverOptions {
	r.udpSkipResolveTarget = skip
	return r
}

func (r ResolverOptions) UdpSkipResolveTarget() bool {
	return r.udpSkipResolveTarget
}

func (s *ResolverOptions) SetUseFakeIP(force bool) *ResolverOptions {
	s.useFakeIP = force
	return s
}

func (s *ResolverOptions) UseFakeIP() bool {
	return s.useFakeIP
}

func (s *ResolverOptions) SetFakeIPSkipCheckUpstream(skip bool) *ResolverOptions {
	s.fakeIPSkipCheckUpstream = skip
	return s
}

func (s *ResolverOptions) FakeIPSkipCheckUpstream() bool {
	return s.fakeIPSkipCheckUpstream
}

func (r ResolverOptions) Opts(reverse bool) []func(*LookupIPOption) {
	switch r.mode {
	case ResolverModePreferIPv6, ResolverModePreferIPv4:
		return []func(*LookupIPOption){func(li *LookupIPOption) {
			if r.mode == ResolverModePreferIPv4 || reverse {
				li.Mode = ResolverModePreferIPv4
			} else {
				li.Mode = ResolverModePreferIPv6
			}
		}}
	}

	return nil
}

type ConnOptions struct {
	bindAddress    *string
	bindInterface  *string
	resolver       *ResolverOptions
	routeMode      config.Mode
	maxminddbGeoip *maxminddb.MaxMindDB
	systemDialer   bool
	skipRoute      bool
	isUdp          bool
}

func (s *ConnOptions) SetBindAddress(str string) *ConnOptions {
	if str == "" {
		return s
	}

	s.bindAddress = &str
	return s
}

func (s *ConnOptions) BindAddress() string {
	if s.bindAddress != nil {
		return *s.bindAddress
	}
	return ""
}

func (s *ConnOptions) SetBindInterface(str string) *ConnOptions {
	if str == "" {
		return s
	}

	s.bindInterface = &str
	return s
}

func (s *ConnOptions) BindInterface() string {
	if s.bindInterface != nil {
		return *s.bindInterface
	}
	return ""
}

func (s *ConnOptions) Resolver() *ResolverOptions {
	if s.resolver == nil {
		s.resolver = &ResolverOptions{}
	}

	return s.resolver
}

func (s *ConnOptions) SetResolver(resolver ResolverOptions) *ConnOptions {
	s.resolver = &resolver
	return s
}

func (s *ConnOptions) SetRouteMode(mode config.Mode) *ConnOptions {
	// skip if already set
	if s.routeMode != config.Mode_bypass {
		return s
	}

	s.routeMode = mode
	return s
}

func (s *ConnOptions) RouteMode() config.Mode {
	return s.routeMode
}

func (s *ConnOptions) SetSystemDialer(systemDialer bool) *ConnOptions {
	s.systemDialer = systemDialer
	return s
}

func (s *ConnOptions) SystemDialer() bool {
	return s.systemDialer
}

func (s *ConnOptions) SetSkipRoute(skip bool) *ConnOptions {
	s.skipRoute = skip
	return s
}

func (s *ConnOptions) SkipRoute() bool {
	return s.skipRoute
}

func (s *ConnOptions) SetIsUdp(isUdp bool) *ConnOptions {
	s.isUdp = isUdp
	return s
}

func (s *ConnOptions) IsUdp() bool {
	return s.isUdp
}

func (s *ConnOptions) SetMaxminddbGeoip(maxminddbGeoip *maxminddb.MaxMindDB) *ConnOptions {
	s.maxminddbGeoip = maxminddbGeoip
	return s
}

func (s *ConnOptions) MaxminddbGeoip() *maxminddb.MaxMindDB {
	return s.maxminddbGeoip
}

type Sniff struct {
	protocol      *string `metrics:"Protocol"`
	process       *string `metrics:"Process"`
	tlsServerName *string `metrics:"TLS Servername"`
	httpHost      *string `metrics:"HTTP Host"`
	processPid    uint    `metrics:"Pid"`
	processUid    uint    `metrics:"Uid"`
}

type AddrInfo struct {
	domainString *string `metrics:"DOMAIN"`
	ipString     *string `metrics:"IP"`
	geo          *string `metrics:"Geo"`
	tag          *string `metrics:"Tag"`
	// dns resolver
	component    *string `metrics:"Component"`
	udpMigrateID uint64  `metrics:"UDP MigrateID"`
}

type Context struct {
	Source      net.Addr `metrics:"Source"`
	Destination net.Addr `metrics:"Destination"`

	context.Context

	inbound       *net.Addr `metrics:"Inbound"`
	inboundName   *string   `metrics:"InboundName"`
	interfaceName *string   `metrics:"InterfaceName"`
	fakeIP        *net.Addr `metrics:"FakeIP"`
	hosts         *net.Addr `metrics:"Hosts"`

	addrInfo *AddrInfo

	sniff *Sniff `metrics:"Sniff"`

	Hash     string `metrics:"Hash"`
	NodeName string `metrics:"NodeName"`

	ruleChain *MatchHistory `metrics:"Rule Chain"`

	Mode config.Mode `metrics:"MODE"`

	connOptions *ConnOptions
}

func (c *Context) NewMatch(ruleName string) {
	if c.ruleChain == nil {
		c.ruleChain = &MatchHistory{}
	}

	c.ruleChain.New(ruleName)
}

func (c *Context) AddMatchHistory(listName string, matched bool) {
	if c.ruleChain == nil {
		c.ruleChain = &MatchHistory{}
	}

	c.ruleChain.Add(listName, matched)
}

func (c *Context) MatchHistory() []*statistic.MatchHistoryEntry {
	if c.ruleChain == nil {
		return nil
	}

	return c.ruleChain.chains
}

func (c *Context) setAddrInfo(f func(*AddrInfo)) {
	if c.addrInfo == nil {
		c.addrInfo = &AddrInfo{}
	}

	f(c.addrInfo)
}

func (s *Context) SetDomainString(str string) *Context {
	if str == "" {
		return s
	}

	s.setAddrInfo(func(a *AddrInfo) {
		a.domainString = &str
	})

	return s
}

func (s *Context) GetDomainString() string {
	if s.addrInfo != nil && s.addrInfo.domainString != nil {
		return *s.addrInfo.domainString
	}
	return ""
}

func (s *Context) SetIPString(str string) *Context {
	if str == "" {
		return s
	}

	s.setAddrInfo(func(a *AddrInfo) {
		a.ipString = &str
	})

	return s
}

func (s *Context) GetIPString() string {
	if s.addrInfo != nil && s.addrInfo.ipString != nil {
		return *s.addrInfo.ipString
	}
	return ""
}

func (s *Context) ConnOptions() *ConnOptions {
	if s.connOptions == nil {
		s.connOptions = &ConnOptions{}
	}

	return s.connOptions
}

func (s *Context) SetTag(str string) *Context {
	if str == "" {
		return s
	}

	s.setAddrInfo(func(a *AddrInfo) {
		a.tag = &str
	})

	return s
}

func (s *Context) GetTag() string {
	if s.addrInfo != nil && s.addrInfo.tag != nil {
		return *s.addrInfo.tag
	}
	return ""
}

func (s *Context) SetComponent(str string) *Context {
	if str == "" {
		return s
	}

	s.setAddrInfo(func(a *AddrInfo) {
		a.component = &str
	})

	return s
}

func (s *Context) GetComponent() string {
	if s.addrInfo != nil && s.addrInfo.component != nil {
		return *s.addrInfo.component
	}
	return ""
}

func (s *Context) SetUDPMigrateID(id uint64) *Context {
	if id == 0 {
		return s
	}

	s.setAddrInfo(func(a *AddrInfo) {
		a.udpMigrateID = id
	})

	return s
}

func (s *Context) GetUDPMigrateID() uint64 {
	if s.addrInfo != nil {
		return s.addrInfo.udpMigrateID
	}
	return 0
}

func (c *Context) GetGeo() string {
	if c.addrInfo != nil && c.addrInfo.geo != nil {
		return *c.addrInfo.geo
	}
	return ""
}

func (c *Context) SetGeo(str string) *Context {
	if str == "" {
		return c
	}

	c.setAddrInfo(func(a *AddrInfo) {
		a.geo = &str
	})
	return c
}

func (c *Context) SetInbound(addr net.Addr) *Context {
	if addr == nil {
		return c
	}

	c.inbound = &addr

	return c
}

func (c *Context) GetInbound() net.Addr {
	if c.inbound != nil {
		return *c.inbound
	}
	return nil
}

func (c *Context) SetInboundName(name string) *Context {
	if name == "" {
		return c
	}

	c.inboundName = &name

	return c
}

func (c *Context) SetInterface(name string) *Context {
	if name == "" {
		return c
	}

	c.interfaceName = &name

	return c
}

func (c *Context) GetInterface() string {
	if c.interfaceName != nil {
		return *c.interfaceName
	}
	return ""
}

func (c *Context) GetInboundName() string {
	if c.inboundName != nil {
		return *c.inboundName
	}
	return ""
}

func (c *Context) SetFakeIP(addr net.Addr) *Context {
	if addr == nil {
		return c
	}

	c.fakeIP = &addr

	return c
}

func (c *Context) GetFakeIP() net.Addr {
	if c.fakeIP != nil {
		return *c.fakeIP
	}
	return nil
}

func (c *Context) SetHosts(addr net.Addr) *Context {
	if addr == nil {
		return c
	}

	c.hosts = &addr

	return c
}

func (c *Context) GetHosts() net.Addr {
	if c.hosts != nil {
		return *c.hosts
	}
	return nil
}

func (c *Context) setSniff(f func(*Sniff)) {
	if c.sniff == nil {
		c.sniff = &Sniff{}
	}

	f(c.sniff)
}

func (c *Context) SetProtocol(p string) *Context {
	if p == "" {
		return c
	}
	c.setSniff(func(s *Sniff) {
		s.protocol = &p
	})
	return c
}

func (c *Context) GetProtocol() string {
	if c.sniff != nil && c.sniff.protocol != nil {
		return *c.sniff.protocol
	}
	return ""
}

func (c *Context) SetProcess(p string, pid, uid uint) *Context {
	if p == "" && pid == 0 && uid == 0 {
		return c
	}

	c.setSniff(func(s *Sniff) {
		s.process = &p
		s.processPid = pid
		s.processUid = uid
	})
	return c
}

func (c *Context) GetProcess() (string, uint, uint) {
	if c.sniff != nil && c.sniff.process != nil {
		return *c.sniff.process, c.sniff.processPid, c.sniff.processUid
	}
	return "", 0, 0
}

func (c *Context) GetProcessName() string {
	if c.sniff != nil && c.sniff.process != nil {
		return *c.sniff.process
	}
	return ""
}

func (c *Context) GetProcessPid() uint {
	if c.sniff != nil {
		return c.sniff.processPid
	}
	return 0
}

func (c *Context) GetProcessUid() uint {
	if c.sniff != nil {
		return c.sniff.processUid
	}
	return 0
}

func (c *Context) SetTLSServerName(str string) *Context {
	if str == "" {
		return c
	}

	c.setSniff(func(s *Sniff) {
		s.tlsServerName = &str
	})
	return c
}

func (c *Context) GetTLSServerName() string {
	if c.sniff != nil && c.sniff.tlsServerName != nil {
		return *c.sniff.tlsServerName
	}
	return ""
}

func (c *Context) SetHTTPHost(str string) *Context {
	if str == "" {
		return c
	}

	c.setSniff(func(s *Sniff) {
		s.httpHost = &str
	})
	return c
}

func (c *Context) GetHTTPHost() string {
	if c.sniff != nil && c.sniff.httpHost != nil {
		return *c.sniff.httpHost
	}
	return ""
}

func (c *Context) SniffHost() string {
	if c.GetTLSServerName() != "" {
		return c.GetTLSServerName()
	}

	return c.GetHTTPHost()
}

func (c *Context) Value(key any) any {
	switch key {
	case contextKey{}:
		return c
	default:
		return c.Context.Value(key)
	}
}

type contextKey struct{}

func WithContext(ctx context.Context) *Context {
	return &Context{
		Context: ctx,
	}
}

func GetContext(ctx context.Context) *Context {
	v, ok := ctx.Value(contextKey{}).(*Context)
	if !ok {
		return &Context{
			Context: ctx,
		}
	}

	return v
}

func GetOrNewContext(ctx context.Context) (context.Context, *Context) {
	v := GetContextOrNil(ctx)
	if v != nil {
		return ctx, v
	}

	c := WithContext(ctx)
	return c, c
}

func GetContextOrNil(ctx context.Context) *Context {
	v, ok := ctx.Value(contextKey{}).(*Context)
	if !ok {
		return nil
	}

	return v
}

func NewDialError(network string, err error, addr net.Addr) *DialError {
	ne := &DialError{}
	if errors.As(err, &ne) {
		return ne
	}

	return &DialError{
		Op:   "dial",
		Net:  network,
		Err:  err,
		Addr: addr,
	}
}

// OpError is the error type usually returned by functions in the net
// package. It describes the operation, network type, and address of
// an error.
type DialError struct {

	// Addr is the network address for which this error occurred.
	// For local operations, like Listen or SetDeadline, Addr is
	// the address of the local endpoint being manipulated.
	// For operations involving a remote network connection, like
	// Dial, Read, or Write, Addr is the remote address of that
	// connection.
	Addr net.Addr

	// Err is the error that occurred during the operation.
	// The Error method panics if the error is nil.
	Err error
	// Op is the operation which caused the error, such as
	// "read" or "write".
	Op string

	// Net is the network type on which this error occurred,
	// such as "tcp" or "udp6".
	Net string

	Sniff string
}

func (e *DialError) Unwrap() error { return e.Err }

func (e *DialError) Error() string {
	if e == nil {
		return "<nil>"
	}
	s := e.Op
	if e.Sniff != "" {
		s += " [sniffed " + e.Sniff + "]"
	}
	if e.Net != "" {
		s += " " + e.Net
	}
	if e.Addr != nil {
		s += " "
		s += e.Addr.String()
	}
	s += ": " + e.Err.Error()
	return s
}

type MatchHistory struct {
	chains []*statistic.MatchHistoryEntry
}

func (r *MatchHistory) New(name string) {
	r.chains = append(r.chains, statistic.MatchHistoryEntry_builder{
		RuleName: &name,
	}.Build())
}

func (r *MatchHistory) Add(listName string, matched bool) {
	if len(r.chains) == 0 {
		return
	}

	history := r.chains[len(r.chains)-1].GetHistory()
	r.chains[len(r.chains)-1].SetHistory(append(history, statistic.MatchResult_builder{
		ListName: &listName,
		Matched:  &matched,
	}.Build()))
}
