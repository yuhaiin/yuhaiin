package cisco

// The server engine: a Cisco-style IPsec remote-access gateway.
//
// It binds two UDP sockets — the IKE port for phase 1 and the NAT-T port for
// everything after the float — and gives each client an IKEv1 Aggressive Mode
// responder that checks the group key, runs XAuth against the user database, and
// assigns an address from the pool. What comes out is a tunnel-mode ESP SA per
// client, all of them added to one dataplane.Pump over one shared TUN: inbound
// packets route by SPI and outbound TUN packets by the client's assigned
// address, which is exactly what the pump is for.
//
// Peers are keyed by initiator cookie for IKE and by inbound SPI for ESP, not by
// remote address: the NAT-T float moves a session to a different port
// mid-exchange, and a NAT rebinding can move it again afterwards, so the address
// is tracked as mutable state rather than used as identity.

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/xen0bit/veepin/dataplane"
	"github.com/xen0bit/veepin/internal/ikev1"
	"github.com/xen0bit/veepin/internal/userdb"
	"github.com/xen0bit/veepin/internal/vlog"
)

// ServerConfig configures the gateway.
type ServerConfig struct {
	// Groups maps a group name to its pre-shared key. A client's Aggressive Mode
	// identity selects which one authenticates it.
	Groups map[string][]byte
	// Users maps a username to its XAuth password.
	Users map[string]string

	// PublicIP is the gateway's outer address as clients reach it. It is hashed
	// into the NAT-D payloads, so a gateway listening on the wildcard — where the
	// socket cannot name it — must be told.
	PublicIP net.IP

	Pool    *dataplane.AddrPool // inner address pool
	Gateway net.IP              // the gateway's own inner address (the pool's first host)
	DNS     []net.IP
	Domain  string
	Banner  string
	// SplitInclude are the destinations clients should route into the tunnel.
	// Empty tells the client nothing, which it reads as "send everything".
	SplitInclude []*net.IPNet

	// Shape is the per-flow downstream shaping budget in bytes; 0 disables it.
	Shape int
	// MTU is the largest inner packet the tunnel carries.
	MTU    int
	Logger *vlog.Logger
}

// Server is a running gateway.
type Server struct {
	cfg      ServerConfig
	ikeConn  *dataplane.PacketConn // port 500: phase 1
	nattConn *dataplane.PacketConn // port 4500: floated IKE + UDP-encapsulated ESP
	tun      tunIO
	pump     *dataplane.Pump
	logger   *vlog.Logger
	gate     *dataplane.Gate

	mu       sync.Mutex
	byCookie map[[8]byte]*serverPeer

	done      chan struct{}
	closeOnce sync.Once
}

// NewServer builds a gateway over the two bound UDP sockets and a TUN.
func NewServer(rawIKE, rawNATT *net.UDPConn, tun tunIO, cfg ServerConfig) (*Server, error) {
	if len(cfg.Groups) == 0 {
		return nil, errors.New("cisco: at least one group is required")
	}
	if len(cfg.Users) == 0 {
		return nil, errors.New("cisco: at least one user is required")
	}
	if cfg.Pool == nil {
		return nil, errors.New("cisco: an address pool is required")
	}
	logger := cfg.Logger
	s := &Server{
		cfg:      cfg,
		ikeConn:  dataplane.NewPacketConn(rawIKE),
		nattConn: dataplane.NewPacketConn(rawNATT),
		tun:      tun,
		logger:   logger,
		gate:     dataplane.NewGate(dataplane.AdmissionConfig{}),
		byCookie: map[[8]byte]*serverPeer{},
		done:     make(chan struct{}),
	}
	s.pump = dataplane.NewPump(tun, s.sendESP, dataplane.SPIDemux, logger.Slog())
	if cfg.MTU > 0 {
		s.pump.SetInnerMTU(cfg.MTU)
	}
	if cfg.Shape > 0 {
		s.pump.SetShaper(dataplane.NewShaper(dataplane.ShapeConfig{Bytes: cfg.Shape}))
		logger.Printf("cisco: downstream shaping on, %d bytes per flow", cfg.Shape)
	}
	return s, nil
}

// sendESP writes one encapsulated packet to a client.
func (s *Server) sendESP(pkt []byte, to *net.UDPAddr) {
	if to == nil {
		return
	}
	_, _ = s.nattConn.WriteToUDP(pkt, to)
}

// Serve runs the gateway until Close. It blocks.
func (s *Server) Serve() error {
	go s.pump.Run()
	go s.recvIKE()
	s.recvNATT()
	return nil
}

// Close stops the gateway.
func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		close(s.done)
		s.pump.Close()
		s.ikeConn.Close()
		s.nattConn.Close()
	})
	return nil
}

// recvIKE reads the plain IKE port. Every datagram here is a bare phase-1
// message — the float moves a session off this socket for good.
func (s *Server) recvIKE() {
	buf := make([]byte, 65535)
	for {
		n, addr, err := s.ikeConn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		s.dispatchIKE(append([]byte(nil), buf[:n]...), addr, false)
	}
}

// recvNATT reads the NAT-T port, where IKE and ESP share a socket and the
// non-ESP marker tells them apart. Reads are batched: one recvmmsg drains up to
// readBatch datagrams under load and blocks like a plain read when idle.
//
// ESP datagrams go to the pump in a batch, which lets it coalesce them for the
// TUN; only IKE is copied out, because the session may retain the message.
func (s *Server) recvNATT() {
	const readBatch = 16
	bufs := make([][]byte, readBatch)
	for i := range bufs {
		bufs[i] = make([]byte, 65535)
	}
	sizes := make([]int, readBatch)
	froms := make([]*net.UDPAddr, readBatch)

	espPkts := make([][]byte, 0, readBatch)
	espFroms := make([]*net.UDPAddr, 0, readBatch)
	for {
		n, err := s.nattConn.ReadBatch(bufs, sizes, froms)
		espPkts, espFroms = espPkts[:0], espFroms[:0]
		for i := range n {
			pkt, addr := bufs[i][:sizes[i]], froms[i]
			if msg, ok := isIKE(pkt); ok {
				s.dispatchIKE(append([]byte(nil), msg...), addr, true)
				continue
			}
			espPkts = append(espPkts, pkt)
			espFroms = append(espFroms, addr)
		}
		if len(espPkts) > 0 {
			s.pump.HandleInboundBatch(espPkts, espFroms)
		}
		if err != nil {
			return
		}
	}
}

// dispatchIKE routes an IKE message to the peer owning its initiator cookie,
// creating a responder for a cookie not seen before.
func (s *Server) dispatchIKE(msg []byte, addr *net.UDPAddr, natt bool) {
	cookie, ok := ikev1.InitiatorCookie(msg)
	if !ok {
		return
	}
	p := s.peerFor(cookie, addr)
	if p == nil {
		return // refused by admission control; already logged
	}
	if !p.established() {
		// Mid-handshake, replies go where the last message came from, as
		// they always have: there is no settled peer to redirect yet.
		p.noteIKEAddr(addr, natt)
		p.ike.HandleInbound(msg)
		return
	}
	// Established, the initiator cookie that routed this message here is
	// cleartext, so the address moves only for a message that verified under
	// the IKE SA. ESP's own return path is the Tunnel's, which the pump moves
	// on authenticated ESP; this is IKE's, which carries DPD.
	if p.ike.HandleInbound(msg) {
		p.noteIKEAddr(addr, natt)
	}
}

// peerFor returns the peer owning an initiator cookie, creating an IKE responder
// for a newly seen one. It returns nil when admission control refuses.
//
// This is where an unauthenticated peer makes the gateway allocate: the cookie
// is chosen by the initiator, so without a bound, traffic with a varying cookie
// creates one IKE responder — with its Diffie-Hellman state — per message.
func (s *Server) peerFor(cookie [8]byte, addr *net.UDPAddr) *serverPeer {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p, ok := s.byCookie[cookie]; ok {
		return p
	}
	if r := s.gate.Admit(addr); r != dataplane.Admitted {
		s.logger.Warnf("cisco: refusing new peer %s: %v", addr, r)
		return nil
	}

	p := &serverPeer{
		srv:    s,
		cookie: cookie,
		addr:   addr,
		// Until the client's floated source port is observed, assume it binds the
		// NAT-T port itself, which an un-NATed peer does.
		nattAddr: &net.UDPAddr{IP: addr.IP, Port: DefaultNATTPort},
	}
	p.ike = ikev1.NewSession(ikev1.Config{
		Role:      ikev1.Responder,
		Mode:      ikev1.ModeAggressive,
		Phase2:    ikev1.Phase2RemoteAccess,
		PSKFor:    s.groupKey,
		XAuth:     &ikev1.XAuthConfig{Authenticate: s.authenticate},
		ModeCfg:   true,
		Assign:    p.assign,
		LocalIP:   s.publicIP(),
		PeerIP:    addr.IP,
		LocalPort: DefaultIKEPort,
		PeerPort:  uint16(addr.Port),
		Send:      p.sendIKE,
		Handler:   p,
		Logger:    s.logger,
	})
	s.byCookie[cookie] = p
	s.logger.Printf("cisco: new peer %s (cookie %x)", addr, cookie)
	return p
}

// groupKey selects a group's pre-shared key. An unknown group is refused here
// rather than allowed to fail later as a hash mismatch, so the log says which.
func (s *Server) groupKey(group string) ([]byte, bool) {
	k, ok := s.cfg.Groups[group]
	return k, ok
}

// authenticate checks XAuth credentials.
// authenticate answers the XAuth exchange. The comparison is constant-time with
// respect to the password (it was a bare ==, which leaked its length), and the
// stored secret may be a bcrypt verifier: XAuth carries the password itself, so
// the gateway never needs to hold one.
func (s *Server) authenticate(user, password string) bool {
	want, ok := s.cfg.Users[user]
	return ok && userdb.Verify(want, password)
}

// publicIP is the address the gateway presents as its own: the configured one,
// else the IKE socket's bound address when it is concrete.
func (s *Server) publicIP() net.IP {
	if s.cfg.PublicIP != nil {
		return s.cfg.PublicIP
	}
	if la, ok := s.ikeConn.LocalAddr().(*net.UDPAddr); ok && !la.IP.IsUnspecified() {
		return la.IP
	}
	return nil
}

// removePeer drops a peer from the index and releases its resources. It is
// idempotent: teardown can re-enter it, and the map-presence check makes the
// second call a no-op.
func (s *Server) removePeer(p *serverPeer, err error) {
	s.mu.Lock()
	if _, ok := s.byCookie[p.cookie]; !ok {
		s.mu.Unlock()
		return
	}
	delete(s.byCookie, p.cookie)
	s.mu.Unlock()

	p.mu.Lock()
	t, ip := p.tunnel, p.innerIP
	p.tunnel = nil
	p.mu.Unlock()

	if t != nil {
		s.pump.RemoveTunnel(t)
	}
	if ip != nil {
		s.cfg.Pool.Release(ip)
	}
	s.logger.Printf("cisco: peer %s gone: %v", p.addr, err)
}

// serverPeer is one client's state on the gateway.
type serverPeer struct {
	srv    *Server
	cookie [8]byte
	ike    *ikev1.Session

	mu       sync.Mutex
	addr     *net.UDPAddr // where phase 1 came from
	nattAddr *net.UDPAddr // where floated IKE and ESP go
	tunnel   *Tunnel
	innerIP  net.IP
}

// noteIKEAddr records where a peer's IKE now comes from. After the float that is
// a new source port, and a NAT rebinding can change it again, so replies follow
// the address the last message actually arrived from.
func (p *serverPeer) noteIKEAddr(addr *net.UDPAddr, natt bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if natt {
		p.nattAddr = addr
	} else {
		p.addr = addr
	}
}

// established reports whether phase 2 has given this peer a tunnel.
func (p *serverPeer) established() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.tunnel != nil
}

func (p *serverPeer) sendIKE(msg []byte, natt bool) error {
	p.mu.Lock()
	ike, nat := p.addr, p.nattAddr
	p.mu.Unlock()
	if natt {
		_, err := p.srv.nattConn.WriteToUDP(markIKE(msg), nat)
		return err
	}
	_, err := p.srv.ikeConn.WriteToUDP(msg, ike)
	return err
}

// assign allocates the client's inner address and renders the configuration
// Mode-Config pushes back. It runs once per session, after XAuth passed.
func (p *serverPeer) assign() (ikev1.ModeCfgReply, error) {
	ip, err := p.srv.cfg.Pool.Allocate()
	if err != nil {
		return ikev1.ModeCfgReply{}, fmt.Errorf("cisco: address pool: %w", err)
	}
	p.mu.Lock()
	p.innerIP = ip
	p.mu.Unlock()

	ones, _ := p.srv.cfg.Pool.Network().Mask.Size()
	return ikev1.ModeCfgReply{
		Address: ip,
		// The client gets the pool's own mask, which puts the gateway's inner
		// address on-link — the shape every other server here hands back.
		Netmask:      net.IP(net.CIDRMask(ones, 32)),
		DNS:          p.srv.cfg.DNS,
		Domain:       p.srv.cfg.Domain,
		Banner:       p.srv.cfg.Banner,
		SplitInclude: p.srv.cfg.SplitInclude,
	}, nil
}

// --- ikev1.Handler ---

func (p *serverPeer) Established(r ikev1.Result) {
	p.mu.Lock()
	ip, to := p.innerIP, p.nattAddr
	p.mu.Unlock()
	if ip == nil {
		p.srv.removePeer(p, errors.New("cisco: no address was assigned"))
		return
	}
	addr, ok := netip.AddrFromSlice(ip.To4())
	if !ok {
		p.srv.removePeer(p, errors.New("cisco: assigned address is not IPv4"))
		return
	}
	// The tunnel carries exactly this client's address: that is what routes TUN
	// egress back to the peer it belongs to.
	t := NewTunnel(newESPSA(r), r.InSPI, []netip.Prefix{netip.PrefixFrom(addr, 32)}, to)

	p.mu.Lock()
	p.tunnel = t
	p.mu.Unlock()
	p.srv.pump.AddTunnel(t)
	p.srv.logger.Printf("cisco: SA established with %s for user %q, assigned %s (spi in=%#x out=%#x)",
		p.addr, r.User, ip, r.InSPI, r.OutSPI)
}

func (p *serverPeer) Failed(err error) { p.srv.removePeer(p, err) }
