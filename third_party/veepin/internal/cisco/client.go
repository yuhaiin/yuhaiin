package cisco

// The client engine: an IKEv1 Aggressive Mode initiator that authenticates with
// a group key and then a user password, pulls an address, and runs a pump over
// the tunnel-mode ESP SA the exchange keyed.
//
// It owns one unconnected UDP socket rather than a dialed one, because NAT-T
// spans two remote ports: phase 1 starts on the gateway's IKE port and floats to
// the NAT-T port, where IKE (behind the non-ESP marker) and ESP then share the
// socket. One local port serves both, which also keeps the source port stable
// across the float — a NAT that saw the pre-float packets keeps the binding.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/xen0bit/veepin/dataplane"
	"github.com/xen0bit/veepin/internal/ikev1"
	"github.com/xen0bit/veepin/internal/vlog"
)

// tunIO is the userspace TUN the data path reads IP from and writes IP to.
// *dataplane.TUN satisfies it; tests supply a fake.
type tunIO interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
}

// ErrAuth reports credentials the gateway rejected — a wrong group key in phase
// 1 or a wrong password in XAuth — so a caller can tell those from a transport
// failure.
var ErrAuth = errors.New("cisco: authentication failed")

// ClientConfig configures the Cisco IPsec client engine.
type ClientConfig struct {
	ServerIP net.IP // the gateway's outer address
	IKEPort  int    // its phase-1 port (default 500)
	NATTPort int    // its NAT-T port for floated IKE and ESP (default 4500)
	LocalIP  net.IP // our outer address, hashed into the NAT-D payloads

	Group    string // the group name, presented as the phase-1 identity
	GroupPSK []byte // that group's pre-shared key
	Username string
	Password string

	// Shape is the per-flow outbound shaping budget in bytes; 0 disables it.
	Shape int
	// MTU is the largest inner packet the tunnel carries.
	MTU    int
	Logger *vlog.Logger
}

// Client is a running Cisco IPsec client.
type Client struct {
	cfg    ClientConfig
	conn   *net.UDPConn
	tun    tunIO
	logger *vlog.Logger

	ikeAddr  *net.UDPAddr // the gateway's IKE port, used until the float
	nattAddr *net.UDPAddr // its NAT-T port: IKE after the float, and all ESP

	ike  *ikev1.Session
	pump *dataplane.Pump

	mu     sync.Mutex
	closed bool

	upCh     chan NetConfig
	done     chan struct{}
	closeErr error
}

// NewClient builds a client over an unconnected UDP socket and a TUN. It sends
// nothing until Handshake.
func NewClient(conn *net.UDPConn, tun tunIO, cfg ClientConfig) *Client {
	logger := cfg.Logger
	ikePort := cfg.IKEPort
	if ikePort == 0 {
		ikePort = DefaultIKEPort
	}
	natt := cfg.NATTPort
	if natt == 0 {
		natt = DefaultNATTPort
	}
	c := &Client{
		cfg:      cfg,
		conn:     conn,
		tun:      tun,
		logger:   logger,
		ikeAddr:  &net.UDPAddr{IP: cfg.ServerIP, Port: ikePort},
		nattAddr: &net.UDPAddr{IP: cfg.ServerIP, Port: natt},
		upCh:     make(chan NetConfig, 1),
		done:     make(chan struct{}),
	}
	var localPort uint16
	if la, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		localPort = uint16(la.Port)
	}
	c.ike = ikev1.NewSession(ikev1.Config{
		Role:      ikev1.Initiator,
		Mode:      ikev1.ModeAggressive,
		Phase2:    ikev1.Phase2RemoteAccess,
		PSK:       cfg.GroupPSK,
		GroupName: cfg.Group,
		XAuth: &ikev1.XAuthConfig{
			Username: cfg.Username,
			Password: cfg.Password,
		},
		ModeCfg:   true,
		LocalIP:   cfg.LocalIP,
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

// Handshake runs IKE and returns the assigned inner addressing once the ESP SA
// is up.
func (c *Client) Handshake(ctx context.Context) (NetConfig, error) {
	go c.recvLoop()
	c.ike.Start()
	select {
	case nc := <-c.upCh:
		return nc, nil
	case <-c.done:
		return NetConfig{}, c.closeErr
	case <-ctx.Done():
		_ = c.Close()
		return NetConfig{}, ctx.Err()
	}
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

// fail closes the client once, recording the first cause.
func (c *Client) fail(err error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	c.closeErr = err
	p := c.pump
	c.mu.Unlock()

	close(c.done)
	_ = c.conn.Close()
	if p != nil {
		p.Close()
	}
}

// recvLoop demultiplexes the socket. On the IKE port every datagram is a bare
// phase-1 message; on the NAT-T port the non-ESP marker tells IKE and ESP apart.
//
// Reads are batched through a dataplane.PacketConn: one recvmmsg drains up to
// readBatch datagrams under load and blocks like a plain read when idle. The
// socket is unconnected — it hears both gateway ports — so the batched reads
// carry sources.
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
			pkt := bufs[i][:sizes[i]]
			if from.Port == c.ikeAddr.Port {
				// IKE handling may retain the message beyond this loop.
				c.ike.HandleInbound(append([]byte(nil), pkt...))
				continue
			}
			if msg, ok := isIKE(pkt); ok {
				c.ike.HandleInbound(append([]byte(nil), msg...))
				continue
			}
			c.mu.Lock()
			p := c.pump
			c.mu.Unlock()
			if p != nil {
				// The pump copies what it keeps, so the buffer is reusable.
				p.HandleInbound(pkt, from)
			}
		}
		if err != nil {
			c.fail(fmt.Errorf("cisco: socket read: %w", err))
			return
		}
	}
}

// --- ikev1.Handler ---

// Established brings the data path up: one tunnel carrying whatever the gateway
// said it carries, and the pump that moves packets through it.
func (c *Client) Established(r ikev1.Result) {
	nc := netConfigFrom(r.ModeCfg)
	// The tunnel carries everything that reaches the TUN. The split-include
	// networks in nc.Routes are advice for the *host* route table — what the
	// caller should send to the TUN in the first place — not a second filter to
	// apply once a packet is already here. Filtering twice would silently drop
	// traffic a caller had deliberately routed in.
	t := NewTunnel(newESPSA(r), r.InSPI, defaultRoutes(), c.nattAddr)

	send := func(pkt []byte, to *net.UDPAddr) {
		if _, err := c.conn.WriteToUDP(pkt, to); err != nil {
			c.fail(fmt.Errorf("cisco: send: %w", err))
		}
	}
	p := dataplane.NewPump(c.tun, send, dataplane.SPIDemux, c.logger.Slog())
	if c.cfg.MTU > 0 {
		p.SetInnerMTU(c.cfg.MTU)
	}
	if c.cfg.Shape > 0 {
		p.SetShaper(dataplane.NewShaper(dataplane.ShapeConfig{Bytes: c.cfg.Shape}))
		c.logger.Printf("cisco: outbound shaping on, %d bytes per flow", c.cfg.Shape)
	}
	p.AddTunnel(t)

	c.mu.Lock()
	c.pump = p
	c.mu.Unlock()

	go p.Run()
	c.logger.Printf("cisco: IPsec SA established (spi in=%#x out=%#x), assigned %s", r.InSPI, r.OutSPI, nc.AssignedIP)
	select {
	case c.upCh <- nc:
	default:
	}
}

// Failed ends the session. Credentials the gateway refused — a wrong group key
// in phase 1, a wrong password in XAuth — are re-wrapped so the caller can say
// which, rather than reporting a bare IKE error.
func (c *Client) Failed(err error) {
	if errors.Is(err, ikev1.ErrAuth) {
		err = fmt.Errorf("%w: %v", ErrAuth, err)
	}
	c.fail(fmt.Errorf("cisco: IKE: %w", err))
}

// probeTimeout bounds one dead-peer-detection round trip. RFC 3706 leaves the
// interval to the implementation; the caller decides how often to ask, and this
// only bounds how long a single question waits for its answer.
const probeTimeout = 5 * time.Second

// Probe implements client.Prober with the protocol's own dead-peer detection,
// so a gateway that has gone away tears the tunnel down instead of blackholing
// it.
func (c *Client) Probe(ctx context.Context) error {
	ack, err := c.ike.Ping()
	if err != nil {
		return err
	}
	timer := time.NewTimer(probeTimeout)
	defer timer.Stop()
	select {
	case <-ack:
		return nil
	case <-c.done:
		return c.closeErr
	case <-timer.C:
		return errors.New("cisco: the gateway did not answer dead-peer detection")
	case <-ctx.Done():
		return ctx.Err()
	}
}
