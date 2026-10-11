package pulse

// The client engine: authenticate, take the configuration the server pushes,
// then run whichever data path it offered.
//
// The configuration phase is a short conversation of its own. The server sends
// the main configuration packet, then — if it offers ESP — a keying packet the
// client answers with its own keys, and finally an end-of-configuration marker.
// Only then does traffic flow.

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"time"

	"github.com/xen0bit/veepin/dataplane"
	"github.com/xen0bit/veepin/internal/ikev2/esp"
	"github.com/xen0bit/veepin/internal/vlog"
)

// TypeConfigDone is the Juniper message type that ends the configuration phase.
const TypeConfigDone = 0x8f

// espProbeTimeout bounds how long the client waits for the server to answer on
// the ESP path before falling back to the IF-T/TLS one. A blocked UDP port is
// the ordinary reason, and the TLS connection is already open for it.
const espProbeTimeout = 4 * time.Second

// espProbeInterval is how long one probe waits for its answer before the next
// goes out.
const espProbeInterval = 200 * time.Millisecond

// Client is an established Pulse tunnel.
type Client struct {
	cfg    Config
	info   LoginInfo
	logger *vlog.Logger

	link *link // the IF-T/TLS carrier: the control channel always, the data path sometimes

	// The ESP path, when one came up.
	pump    *dataplane.Pump
	espConn *net.UDPConn
}

// AssignedConfig is the configuration the server pushed.
func (c *Client) AssignedConfig() Config { return c.cfg }

// Session is the login the exchange produced.
func (c *Client) Session() LoginInfo { return c.info }

// OverESP reports which data path is carrying traffic, for logs and tests.
func (c *Client) OverESP() bool { return c.pump != nil }

// Connect authenticates over conn, takes the configuration, and brings a data
// path up. conn must be an established TLS connection to the server.
//
// wantESP asks for the ESP data path where the server offers one; shape is the
// per-flow outbound shaping budget in bytes, and 0 disables it.
func Connect(conn net.Conn, host, path, user, password, hostname string,
	tun io.ReadWriteCloser, logger *vlog.Logger, wantESP bool, shape int,
) (*Client, error) {
	if logger == nil {
		logger = vlog.Discard()
	}
	s, info, err := ClientAuth(conn, host, path, user, password, hostname)
	if err != nil {
		return nil, err
	}

	cfg, serverKeys, myKeys, err := clientConfigPhase(s, logger)
	if err != nil {
		return nil, err
	}
	if cfg.Address == nil {
		return nil, errors.New("pulse: the server assigned no address")
	}

	c := &Client{cfg: cfg, info: info, logger: logger}
	c.link = newLink(conn, tun, logger)
	c.link.closeTUN = tun.Close

	if wantESP && serverKeys != nil && cfg.ESPPort > 0 {
		if err := c.startESP(conn, cfg, myKeys, serverKeys, tun, shape); err == nil {
			// The TLS connection stays open as the control channel: the server
			// rekeys ESP over it, and it is the fallback if ESP stops working.
			go c.link.readLoop()
			return c, nil
		} else {
			logger.Printf("pulse: ESP unavailable (%v), staying on the IF-T/TLS data path", err)
		}
	}

	go c.link.readLoop()
	go c.link.tunLoop(shaperTarget(shape, cfg.MTU, logger))
	return c, nil
}

// shaperTarget builds the padding decision the TUN loop consults, or nil when
// shaping is off.
func shaperTarget(shape, mtu int, logger *vlog.Logger) func([]byte) int {
	if shape <= 0 {
		return nil
	}
	if mtu <= 0 {
		mtu = maxInnerPacket
	}
	sh := dataplane.NewShaper(dataplane.ShapeConfig{Bytes: shape})
	logger.Printf("pulse: outbound shaping on, %d bytes per flow", shape)
	return func(pkt []byte) int { return sh.Target(pkt, mtu) }
}

// clientConfigPhase reads the server's configuration packets until it says it
// is done, answering the ESP keying packet on the way.
func clientConfigPhase(s *stream, logger *vlog.Logger) (Config, *Keys, *Keys, error) {
	var cfg Config
	var serverKeys, myKeys *Keys
	var haveConfig bool

	for {
		m, err := s.recv()
		if err != nil {
			return cfg, nil, nil, fmt.Errorf("pulse: reading the configuration: %w", err)
		}
		if m.Vendor != VendorJuniper {
			continue
		}
		switch m.Type {
		case TypeConfigDone:
			if !haveConfig {
				return cfg, nil, nil, errors.New("pulse: the server finished configuring without sending a configuration")
			}
			return cfg, serverKeys, myKeys, nil
		case TypeConfig:
		default:
			continue
		}
		if len(m.Payload) < espSigOffset+4 {
			return cfg, nil, nil, errors.New("pulse: configuration packet too short to identify")
		}
		switch binary.BigEndian.Uint32(m.Payload[espSigOffset:]) {
		case SigConfig, SigConfigR14:
			if cfg, err = ParseConfig(m.Payload); err != nil {
				return cfg, nil, nil, err
			}
			haveConfig = true
		case SigESP:
			if !haveConfig {
				return cfg, nil, nil, errors.New("pulse: ESP keys arrived before the configuration naming their algorithms")
			}
			k, block, perr := ParseESPPacket(m.Payload, cfg.ESPEncryption, cfg.ESPHMAC)
			if perr != nil {
				// A keying packet this client cannot use is not fatal: the
				// IF-T/TLS data path is still there, and saying so is more
				// useful than refusing the whole session.
				logger.Printf("pulse: ignoring the ESP keys (%v)", perr)
				continue
			}
			serverKeys = k

			mine, gerr := GenerateKeys(cfg.ESPEncryption, cfg.ESPHMAC)
			if gerr != nil {
				return cfg, nil, nil, gerr
			}
			resp, berr := BuildESPResponse(mine, block)
			if berr != nil {
				return cfg, nil, nil, berr
			}
			if err := s.send(VendorJuniper, TypeConfig, resp); err != nil {
				return cfg, nil, nil, err
			}
			// "ncmo=1" tells the server the client has the keys and it may
			// start sending ESP.
			if err := s.sendLine(VendorJuniper, TypeControl, "ncmo=1\n"); err != nil {
				return cfg, nil, nil, err
			}
			myKeys = mine
		}
	}
}

// startESP brings the ESP data path up and proves it carries traffic.
func (c *Client) startESP(conn net.Conn, cfg Config, myKeys, serverKeys *Keys,
	tun io.ReadWriteCloser, shape int,
) error {
	if myKeys == nil {
		return errors.New("pulse: no client keys were generated")
	}
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return err
	}
	serverIP := net.ParseIP(host)
	if serverIP == nil {
		return fmt.Errorf("pulse: cannot read the server address from %q", host)
	}
	peer := &net.UDPAddr{IP: serverIP, Port: cfg.ESPPort}
	udp, err := net.DialUDP("udp", nil, peer)
	if err != nil {
		return fmt.Errorf("pulse: dialing the ESP path: %w", err)
	}

	// The server's block is what this client stamps on packets it sends; the
	// block it sent itself is what the server stamps on packets coming back.
	// See the matching note in the server's awaitESPResponse.
	sa, err := NewSA(serverKeys, myKeys)
	if err != nil {
		_ = udp.Close()
		return err
	}
	if err := probeESP(udp, sa, cfg.Address); err != nil {
		_ = udp.Close()
		return err
	}

	c.espConn = udp
	send := func(pkt []byte, _ *net.UDPAddr) {
		if _, werr := udp.Write(pkt); werr != nil {
			c.link.stop(werr)
		}
	}
	c.pump = dataplane.NewPump(tun, send, dataplane.SPIDemux, c.logger.Slog())
	if cfg.MTU > 0 {
		c.pump.SetInnerMTU(cfg.MTU)
	}
	if shape > 0 {
		c.pump.SetShaper(dataplane.NewShaper(dataplane.ShapeConfig{Bytes: shape}))
		c.logger.Printf("pulse: outbound shaping on, %d bytes per flow", shape)
	}
	c.pump.AddTunnel(NewTunnel(sa, sa.SPIIn, defaultRoutes(), peer))

	go c.pump.Run()
	go c.readESP()
	c.logger.Printf("pulse: ESP path up on UDP %d", cfg.ESPPort)
	return nil
}

// probeESP proves the ESP path carries traffic in both directions before the
// client commits to it.
//
// The probe is the one this protocol family defines: a single zero octet, with
// the next-header field naming the inner family, echoed back unchanged. It is
// not an IP packet, so the peer routes nothing; getting the same octet back is
// the proof.
func probeESP(conn *net.UDPConn, sa *esp.SA, src net.IP) error {
	nextHeader := byte(4)
	if src.To4() == nil {
		nextHeader = 41
	}
	pkt, err := sa.Encapsulate([]byte{0}, nextHeader)
	if err != nil {
		return fmt.Errorf("pulse: protecting the ESP probe: %w", err)
	}
	buf := make([]byte, 2048)
	deadline := time.Now().Add(espProbeTimeout)
	for time.Now().Before(deadline) {
		if _, err := conn.Write(pkt); err != nil {
			return fmt.Errorf("pulse: sending the ESP probe: %w", err)
		}
		// Probe often rather than waiting long: the usual reason the first one
		// goes unanswered is that the server has not finished reading the
		// keying response yet, which is a matter of milliseconds. A blocked UDP
		// port, the other reason, is not going to unblock either way.
		if err := conn.SetReadDeadline(time.Now().Add(espProbeInterval)); err != nil {
			return err
		}
		n, rerr := conn.Read(buf)
		if rerr != nil {
			continue
		}
		if inner, _, derr := sa.Decapsulate(buf[:n]); derr == nil && len(inner) == 1 && inner[0] == 0 {
			_ = conn.SetReadDeadline(time.Time{})
			return nil
		}
	}
	return errors.New("pulse: the server did not answer on the ESP path")
}

// defaultRoutes is every destination in both families: what a client's single
// tunnel carries. The server's split-include list is advice for the host route
// table, not a second filter to apply here.
func defaultRoutes() []netip.Prefix {
	return []netip.Prefix{
		netip.PrefixFrom(netip.IPv4Unspecified(), 0),
		netip.PrefixFrom(netip.IPv6Unspecified(), 0),
	}
}

// readESP feeds inbound datagrams to the pump.
func (c *Client) readESP() {
	buf := make([]byte, maxInnerPacket)
	for {
		n, err := c.espConn.Read(buf)
		if err != nil {
			c.link.stop(err)
			return
		}
		c.pump.HandleInbound(buf[:n], nil)
	}
}

// Wait blocks until the tunnel stops.
func (c *Client) Wait() error { return c.link.Wait() }

// Close tears the tunnel down.
func (c *Client) Close() error {
	if c.pump != nil {
		c.pump.Close()
	}
	if c.espConn != nil {
		_ = c.espConn.Close()
	}
	return c.link.Close()
}

// probeIdle is how long the ESP path may go without an authenticated inbound
// packet before a probe calls it dead.
const probeIdle = 30 * time.Second

// Probe implements client.Prober.
//
// On the ESP path the pump's own record of authenticated inbound traffic is the
// evidence. On the IF-T/TLS path the carrier is TCP, so a server that has gone
// away is reported by the connection itself — a probe there only has to notice
// that the link has already stopped.
func (c *Client) Probe(ctx context.Context) error {
	select {
	case <-c.link.done:
		if err := c.link.Wait(); err != nil {
			return err
		}
		return errors.New("pulse: the session ended")
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	if c.pump != nil {
		if idle := c.pump.IdleFor(); idle > probeIdle {
			return fmt.Errorf("pulse: no authenticated ESP for %s", idle.Truncate(time.Second))
		}
	}
	return nil
}
