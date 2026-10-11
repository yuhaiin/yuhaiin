package l2tp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/xen0bit/veepin/dataplane"
	"github.com/xen0bit/veepin/internal/ikev1"
	"github.com/xen0bit/veepin/internal/ikev2/esp"
	"github.com/xen0bit/veepin/internal/mschap"
	"github.com/xen0bit/veepin/internal/ppp"
	"github.com/xen0bit/veepin/internal/vlog"
)

// tunIO is the userspace TUN the data path reads IP from and writes IP to.
// *dataplane.TUN satisfies it; tests supply a fake.
type tunIO interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
}

// ClientConfig configures the L2TP/IPsec client engine.
type ClientConfig struct {
	ServerIP net.IP // the server's outer address (IKE peer, phase-2 selector)
	IKEPort  int    // the server's Main Mode port (default 500)
	NATTPort int    // the server's NAT-T port for floated IKE and ESP (default 4500)
	LocalIP  net.IP // our outer address, as the ID payload and phase-2 selector
	PSK      []byte
	Username string
	Password string
	DNS      []net.IP
	Logger   *vlog.Logger
}

// NetConfig is the inner addressing PPP/IPCP assigned the client, which the
// caller applies to its TUN.
type NetConfig struct {
	AssignedIP net.IP
	Netmask    net.IP
	Gateway    net.IP // the server's inner address
	DNS        []net.IP
}

// Client is a running L2TP/IPsec client: an IKEv1 initiator whose completed
// exchange keys an ESP transport SA, inside which an L2TP LAC tunnel carries a
// PPP session over a TUN.
//
// It owns one unconnected UDP socket rather than a dialed one, because NAT-T
// spans two remote ports: Main Mode starts on the peer's IKE port and floats to
// the NAT-T port, where IKE (behind the non-ESP marker) and ESP then share the
// socket. One local port serves both, which also keeps the source port stable
// across the float.
type Client struct {
	cfg    ClientConfig
	conn   *net.UDPConn
	tun    tunIO
	logger *vlog.Logger

	ikeAddr  *net.UDPAddr // peer's IKE port, used until the float
	nattAddr *net.UDPAddr // peer's NAT-T port: IKE after the float, and all ESP

	localIP net.IP
	ike     *ikev1.Session

	mu     sync.Mutex
	sa     *esp.SA
	tunnel *Tunnel
	ppp    *ppp.Session
	closed bool

	upCh     chan NetConfig
	done     chan struct{}
	closeErr error
}

// NewClient builds a client over an unconnected UDP socket and a TUN. cfg.IKEPort
// is the peer's Main Mode port; the NAT-T port is fixed by RFC 3948.
func NewClient(conn *net.UDPConn, tun tunIO, cfg ClientConfig) *Client {
	logger := cfg.Logger
	ikePort := cfg.IKEPort
	if ikePort == 0 {
		ikePort = defaultIKEPort
	}
	natt := cfg.NATTPort
	if natt == 0 {
		natt = nattPort
	}
	c := &Client{
		cfg:      cfg,
		conn:     conn,
		tun:      tun,
		logger:   logger,
		ikeAddr:  &net.UDPAddr{IP: cfg.ServerIP, Port: ikePort},
		nattAddr: &net.UDPAddr{IP: cfg.ServerIP, Port: natt},
		localIP:  cfg.LocalIP,
		upCh:     make(chan NetConfig, 1),
		done:     make(chan struct{}),
	}
	var localPort uint16
	if la, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		localPort = uint16(la.Port)
	}
	c.ike = ikev1.NewSession(ikev1.Config{
		Role:      ikev1.Initiator,
		PSK:       cfg.PSK,
		LocalIP:   c.localIP,
		PeerIP:    cfg.ServerIP,
		LocalPort: localPort,
		PeerPort:  uint16(ikePort),
		Send:      c.sendIKE,
		Handler:   c,
		Logger:    logger,
	})
	return c
}

// sendIKE transmits an IKE message on whichever port the exchange is currently
// using: bare on the IKE port before the float, marked as non-ESP on the NAT-T
// port after it.
func (c *Client) sendIKE(msg []byte, natt bool) error {
	if natt {
		_, err := c.conn.WriteToUDP(markIKE(msg), c.nattAddr)
		return err
	}
	_, err := c.conn.WriteToUDP(msg, c.ikeAddr)
	return err
}

// Handshake runs IKE, brings up the ESP SA, L2TP session and PPP link, and
// returns the assigned inner addressing once IPCP completes.
func (c *Client) Handshake(ctx context.Context) (NetConfig, error) {
	go c.recvLoop()
	c.ike.Start()
	select {
	case nc := <-c.upCh:
		return nc, nil
	case <-c.done:
		return NetConfig{}, c.closeErr
	case <-ctx.Done():
		c.Close()
		return NetConfig{}, ctx.Err()
	}
}

// Probe sends an L2TP HELLO and waits for the peer to acknowledge it.
//
// This protocol nests two things that can go quiet independently: an ESP
// transport SA and an L2TP control connection inside it. A HELLO exercises
// both, because the acknowledgement has to come back up the same path -- which
// is why the probe is here and not a bare ESP liveness check. Neither end sends
// unprompted traffic on an idle tunnel, so without this the socket stays up and
// nothing ever notices the far end is gone.
func (c *Client) Probe(ctx context.Context) error {
	c.mu.Lock()
	t, closed := c.tunnel, c.closed
	c.mu.Unlock()
	if closed || t == nil {
		return ErrTunnelClosed
	}
	return t.SendHello(ctx)
}

// Wait blocks until the tunnel closes.
func (c *Client) Wait() error {
	<-c.done
	return c.closeErr
}

// Close tears the tunnel down.
func (c *Client) Close() error {
	c.fail(nil)
	return c.closeErr
}

// fail closes the client once. It guards with a plain flag (not sync.Once)
// because tearing the tunnel down re-enters this method via the tunnel's Closed
// callback; a flag makes that reentrant call a no-op, where a Once would
// deadlock.
func (c *Client) fail(err error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	c.closeErr = err
	t := c.tunnel
	c.mu.Unlock()

	close(c.done)
	c.conn.Close()
	if t != nil {
		t.Close()
	}
}

// recvLoop demultiplexes the socket. On the IKE port every datagram is a bare
// IKE message; on the NAT-T port the non-ESP marker tells IKE and ESP apart.
// Reads are batched through a dataplane.PacketConn (the socket is unconnected —
// it hears both server ports — so the batched reads must carry sources): one
// recvmmsg drains up to readBatch datagrams under load and blocks like a plain
// read when idle. As on the server side, every datagram is still copied out,
// because L2TP control handling may alias the packet beyond this loop.
func (c *Client) recvLoop() {
	const readBatch = 16
	pc := dataplane.NewPacketConn(c.conn)
	bufs := make([][]byte, readBatch)
	for i := range bufs {
		bufs[i] = make([]byte, 65535)
	}
	sizes := make([]int, readBatch)
	froms := make([]*net.UDPAddr, readBatch)
	for {
		n, err := pc.ReadBatch(bufs, sizes, froms)
		for i := range n {
			from := froms[i]
			if !from.IP.Equal(c.cfg.ServerIP) {
				continue
			}
			pkt := append([]byte(nil), bufs[i][:sizes[i]]...)
			if from.Port == c.ikeAddr.Port {
				c.ike.HandleInbound(pkt)
				continue
			}
			if msg, ok := isIKE(pkt); ok {
				c.ike.HandleInbound(msg)
				continue
			}
			c.handleESP(pkt)
		}
		if err != nil {
			c.fail(fmt.Errorf("l2tp: socket read: %w", err))
			return
		}
	}
}

func (c *Client) handleESP(pkt []byte) {
	c.mu.Lock()
	sa, tun := c.sa, c.tunnel
	c.mu.Unlock()
	if sa == nil || tun == nil {
		return
	}
	inner, nh, err := sa.Decapsulate(pkt)
	if err != nil || nh != ipProtoUDP {
		return
	}
	if l2, ok := unwrapUDP(inner); ok {
		tun.HandleInbound(l2)
	}
}

// --- ikev1.Handler ---

func (c *Client) Established(r ikev1.Result) {
	c.mu.Lock()
	c.sa = newESPSA(r)
	c.tunnel = NewTunnel(RoleLAC, c.espSend, c)
	tun := c.tunnel
	c.mu.Unlock()
	c.logger.Printf("l2tp: IPsec SA established, starting L2TP tunnel")
	tun.Start()
}

func (c *Client) Failed(err error) { c.fail(fmt.Errorf("l2tp: IKE: %w", err)) }

// espSend wraps an L2TP datagram in a transport-mode ESP packet and sends it.
func (c *Client) espSend(l2tp []byte) error {
	c.mu.Lock()
	sa := c.sa
	c.mu.Unlock()
	if sa == nil {
		return errors.New("l2tp: ESP SA not ready")
	}
	pkt, err := sa.Encapsulate(wrapUDP(l2tp), ipProtoUDP)
	if err != nil {
		return err
	}
	_, err = c.conn.WriteToUDP(pkt, c.nattAddr)
	return err
}

// --- l2tp.Handler ---

func (c *Client) SessionUp() {
	c.mu.Lock()
	c.ppp = ppp.New(c.cfg.Username, c.cfg.Password, c.tunnel, clientPPP{c})
	p := c.ppp
	c.mu.Unlock()
	c.logger.Printf("l2tp: L2TP session up, starting PPP")
	p.Start()
}

func (c *Client) DataFrame(frame []byte) {
	if ip, ok := ppp.IsIP(frame); ok {
		_, _ = c.tun.Write(ip)
		return
	}
	c.mu.Lock()
	p := c.ppp
	c.mu.Unlock()
	if p != nil {
		p.Receive(frame)
	}
}

func (c *Client) Closed(err error) { c.fail(err) }

// clientPPP adapts Client to ppp.Handler.
type clientPPP struct{ c *Client }

func (h clientPPP) Authenticated(nt [mschap.NTResponseLen]byte) {}

func (h clientPPP) NetworkUp(cfg ppp.IPConfig) {
	c := h.c
	c.logger.Printf("l2tp: PPP up, address %s gateway %s", cfg.LocalIP, cfg.PeerIP)
	go c.tunToTunnel()
	dns := cfg.DNS
	if len(dns) == 0 {
		dns = c.cfg.DNS
	}
	select {
	case c.upCh <- NetConfig{
		AssignedIP: cfg.LocalIP,
		Netmask:    net.IPv4(255, 255, 255, 255),
		Gateway:    cfg.PeerIP,
		DNS:        dns,
	}:
	default:
	}
}

func (h clientPPP) Closed(err error) { h.c.fail(err) }

// tunToTunnel pumps IP packets from the TUN into the PPP/L2TP/ESP stack.
func (c *Client) tunToTunnel() {
	buf := make([]byte, 65535)
	for {
		n, err := c.tun.Read(buf)
		if err != nil {
			c.fail(fmt.Errorf("l2tp: TUN read: %w", err))
			return
		}
		c.mu.Lock()
		tun := c.tunnel
		c.mu.Unlock()
		if tun == nil {
			return
		}
		if err := tun.SendPPP(ppp.EncapsulateIP(append([]byte(nil), buf[:n]...))); err != nil {
			c.fail(fmt.Errorf("l2tp: send: %w", err))
			return
		}
	}
}
