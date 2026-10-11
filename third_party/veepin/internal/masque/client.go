package masque

// The client engine: open a CONNECT-IP tunnel, take the address the proxy
// assigns, then move packets between the TUN and the request stream.
//
// The structure is the one every veepin client follows — a handshake that
// returns what the server assigned and installs nothing, then a data path — but
// the transport is inverted from the UDP protocols. There is no socket read loop
// and no replay window here: QUIC has already authenticated the peer with TLS,
// delivered the stream reliably and in order, and will migrate the connection
// itself. What remains is capsules in and capsules out.

import (
	"context"
	"fmt"
	"io"
	"net/netip"
	"sync"

	"github.com/xen0bit/veepin/internal/masque/http3"
	"github.com/xen0bit/veepin/internal/vlog"
	"golang.org/x/net/quic"
)

// maxInnerPacket bounds a packet read from the TUN. It is generous: the MTU is
// smaller, but a misconfigured interface can present a larger frame and it
// should be dropped, not truncated into the tunnel.
const maxInnerPacket = 65535

// tunDevice is the subset of dataplane.TUN the engine uses, named so the engine
// can be tested against an in-memory pipe.
type tunDevice interface {
	io.ReadWriteCloser
}

// ClientConfig is what the client engine needs beyond an established QUIC
// connection and a TUN.
type ClientConfig struct {
	// Authority is the :authority the CONNECT request carries — the proxy's
	// host, which it may use to select a tunnel endpoint.
	Authority string
	// Logger receives progress messages; nil discards them.
	Logger *vlog.Logger
}

// Client is an established CONNECT-IP tunnel.
type Client struct {
	h3  *http3.Conn
	rs  *http3.RequestStream
	tun tunDevice
	log *vlog.Logger

	assigned netip.Prefix
	routes   []RouteEntry

	done      chan struct{}
	closeOnce sync.Once
}

// Assigned reports the address the proxy assigned to this client.
func (c *Client) Assigned() netip.Prefix { return c.assigned }

// Routes reports the ranges the proxy advertised as reachable through the
// tunnel.
func (c *Client) Routes() []RouteEntry { return c.routes }

// Connect performs the CONNECT-IP handshake over an established QUIC connection:
// the HTTP/3 setup, the Extended CONNECT, and the address assignment. It returns
// a Client whose data path has not started; StartClient wires that to a TUN.
func Connect(ctx context.Context, qc *quic.Conn, cfg ClientConfig) (*http3.Conn, *http3.RequestStream, netip.Prefix, []RouteEntry, error) {
	h3conn, err := http3.Client(ctx, qc)
	if err != nil {
		return nil, nil, netip.Prefix{}, nil, fmt.Errorf("masque: http/3 setup: %w", err)
	}

	path := ConnectIPPath("*", "*")
	rs, err := h3conn.OpenConnect(ctx, ConnectIPHeaders(cfg.Authority, path))
	if err != nil {
		return nil, nil, netip.Prefix{}, nil, fmt.Errorf("masque: opening CONNECT-IP: %w", err)
	}

	resp, err := rs.ReadResponse()
	if err != nil {
		return nil, nil, netip.Prefix{}, nil, fmt.Errorf("masque: reading CONNECT response: %w", err)
	}
	if status := fieldValue(resp, ":status"); status != "200" {
		return nil, nil, netip.Prefix{}, nil, fmt.Errorf("masque: proxy refused CONNECT-IP: status %q", status)
	}

	// Ask for an address with no preference, so a proxy that waits for a request
	// rather than assigning unsolicited still responds.
	req := EncodeAddresses([]AddressEntry{{RequestID: 1, Prefix: netip.PrefixFrom(netip.IPv4Unspecified(), 0)}})
	if err := WriteCapsule(rs, CapsuleAddressRequest, req); err != nil {
		return nil, nil, netip.Prefix{}, nil, fmt.Errorf("masque: sending ADDRESS_REQUEST: %w", err)
	}

	assigned, routes, err := readAssignment(rs)
	if err != nil {
		return nil, nil, netip.Prefix{}, nil, err
	}
	return h3conn, rs, assigned, routes, nil
}

// readAssignment reads capsules until the proxy assigns an address, collecting
// any routes advertised along the way. A capsule budget bounds a proxy that
// talks without ever assigning.
func readAssignment(rs *http3.RequestStream) (netip.Prefix, []RouteEntry, error) {
	var routes []RouteEntry
	for range 16 {
		c, err := ReadCapsule(rs)
		if err != nil {
			return netip.Prefix{}, nil, fmt.Errorf("masque: awaiting address assignment: %w", err)
		}
		switch c.Type {
		case CapsuleAddressAssign:
			addrs, err := ParseAddresses(c.Value)
			if err != nil {
				return netip.Prefix{}, nil, fmt.Errorf("masque: ADDRESS_ASSIGN: %w", err)
			}
			if len(addrs) == 0 {
				return netip.Prefix{}, nil, fmt.Errorf("masque: proxy assigned no address")
			}
			return addrs[0].Prefix, routes, nil
		case CapsuleRouteAdvertisement:
			if r, err := ParseRoutes(c.Value); err == nil {
				routes = append(routes, r...)
			}
		default:
			// A capsule type we do not act on before assignment; ignore it.
		}
	}
	return netip.Prefix{}, nil, fmt.Errorf("masque: proxy sent no ADDRESS_ASSIGN")
}

// StartClient runs the data path over an established tunnel and TUN.
func StartClient(h3conn *http3.Conn, rs *http3.RequestStream, tun tunDevice, assigned netip.Prefix, routes []RouteEntry, logger *vlog.Logger) *Client {
	if logger == nil {
		logger = vlog.Discard()
	}
	c := &Client{
		h3:       h3conn,
		rs:       rs,
		tun:      tun,
		log:      logger,
		assigned: assigned,
		routes:   routes,
		done:     make(chan struct{}),
	}
	go c.tunToStream()
	go c.streamToTun()
	return c
}

// tunToStream reads inner packets from the TUN and sends each as a DATAGRAM
// capsule.
func (c *Client) tunToStream() {
	buf := make([]byte, maxInnerPacket)
	// One encoder for the life of the loop, so a steady-state tunnel allocates
	// nothing per packet.
	var enc DatagramEncoder
	for {
		n, err := c.tun.Read(buf)
		if err != nil {
			c.stop(fmt.Errorf("masque: TUN read: %w", err))
			return
		}
		if _, err := c.rs.Write(enc.Encode(buf[:n])); err != nil {
			c.stop(fmt.Errorf("masque: sending datagram: %w", err))
			return
		}
	}
}

// streamToTun reads capsules and writes the inner packets to the TUN. A capsule
// that is not a datagram (a mid-session route update, say) is handled without
// disturbing the data path.
func (c *Client) streamToTun() {
	// The reader's buffer is reused, so Value is only valid until the next Read.
	// Nothing here keeps it: the TUN write copies, and ParseRoutes decodes into
	// values rather than aliasing.
	var cr CapsuleReader
	for {
		capsule, err := cr.Read(c.rs)
		if err != nil {
			c.stop(fmt.Errorf("masque: reading capsule: %w", err))
			return
		}
		switch capsule.Type {
		case CapsuleDatagram:
			ip, ok, err := DecodeDatagramPayload(capsule.Value)
			if err != nil || !ok {
				continue
			}
			if _, err := c.tun.Write(ip); err != nil {
				c.stop(fmt.Errorf("masque: TUN write: %w", err))
				return
			}
		case CapsuleRouteAdvertisement:
			if r, err := ParseRoutes(capsule.Value); err == nil {
				c.routes = append(c.routes, r...)
				c.log.Printf("masque: proxy advertised %d additional route(s)", len(r))
			}
		default:
			// ADDRESS_ASSIGN updates and unknown capsules are not acted on here.
		}
	}
}

// Wait blocks until the tunnel stops or ctx is cancelled.
func (c *Client) Wait(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.done:
		return nil
	}
}

// stop tears the client down, recording the first cause.
func (c *Client) stop(cause error) {
	c.closeOnce.Do(func() {
		if cause != nil {
			c.log.Printf("%v", cause)
		}
		close(c.done)
		_ = c.rs.Close()
		_ = c.h3.Close()
		_ = c.tun.Close()
	})
}

// Close tears the tunnel down.
func (c *Client) Close() error {
	c.stop(nil)
	return nil
}

// Done is closed when the client stops.
func (c *Client) Done() <-chan struct{} { return c.done }

// fieldValue returns the value of a header field, or "".
func fieldValue(fields []http3.Field, name string) string {
	for _, f := range fields {
		if f.Name == name {
			return f.Value
		}
	}
	return ""
}
