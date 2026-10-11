package toy

// The client engine: run the handshake, then hand the socket to the pump.
//
// The structure here is the one every veepin client follows. Dial does the
// handshake and returns what the server assigned; it installs no addresses and
// no routes, because that is the caller's decision. Everything after the
// handshake is the data path, and the data path is dataplane.Pump.

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/xen0bit/veepin/dataplane"
	"github.com/xen0bit/veepin/internal/vlog"
)

// Handshake retransmission. There is no reliability layer, so an unanswered
// message is simply resent until the budget is spent.
const (
	retryInterval = 1 * time.Second
	maxAttempts   = 10

	// KeepaliveInterval is how often an idle peer sends a KEEPALIVE, which also
	// holds a NAT binding open.
	KeepaliveInterval = 15 * time.Second
)

// ClientConfig is what the client engine needs.
type ClientConfig struct {
	// Server is the resolved server address.
	Server *net.UDPAddr
	// User is the identity presented in HELLO.
	User string
	// Secret is the shared secret. See SPEC.md for why this protects nothing.
	Secret string
	// Logger receives progress messages; nil discards them.
	Logger *vlog.Logger
}

// Client is an established client session.
type Client struct {
	conn    *net.UDPConn
	session *Session
	pump    *dataplane.Pump
	tun     *dataplane.TUN
	log     *vlog.Logger

	// Welcome is what the server assigned.
	Welcome Welcome

	done chan struct{}
}

// Handshake performs the TOY handshake over conn and returns the established
// session. It does not start a data path.
//
// Splitting this from the data path is what makes the engine testable without a
// TUN, and it is why the interop harness can exercise the handshake against an
// independent implementation.
func Handshake(ctx context.Context, conn *net.UDPConn, cfg ClientConfig) (*Session, Welcome, error) {
	logger := cfg.Logger
	if len(cfg.User) > 255 {
		return nil, Welcome{}, errors.New("toy: username longer than 255 octets")
	}

	var clientNonce [NonceLen]byte
	if _, err := rand.Read(clientNonce[:]); err != nil {
		return nil, Welcome{}, fmt.Errorf("toy: generating nonce: %w", err)
	}

	hello := AppendHeader(nil, Header{Type: MsgHello, Counter: 1})
	hello = AppendHello(hello, Hello{Nonce: clientNonce, User: cfg.User})

	// Step 1-2: HELLO until CHALLENGE.
	challenge, hdr, err := exchange(ctx, conn, cfg.Server, hello, MsgChallenge, logger, "HELLO")
	if err != nil {
		return nil, Welcome{}, err
	}
	serverNonce, err := ParseFixed(challenge, NonceLen)
	if err != nil {
		return nil, Welcome{}, fmt.Errorf("toy: CHALLENGE: %w", err)
	}
	session := hdr.Session
	if session == 0 {
		return nil, Welcome{}, errors.New("toy: server assigned session 0, which is reserved")
	}

	key := DeriveKey(cfg.Secret, clientNonce[:], serverNonce)
	proof := Proof(cfg.Secret, clientNonce[:], serverNonce)

	auth := AppendHeader(nil, Header{Type: MsgAuth, Session: session, Counter: 2})
	auth = AppendNonce(auth, proof[:])

	// Step 3-4: AUTH until WELCOME (or REJECT, which exchange surfaces).
	welcomeBody, _, err := exchange(ctx, conn, cfg.Server, auth, MsgWelcome, logger, "AUTH")
	if err != nil {
		return nil, Welcome{}, err
	}
	welcome, err := ParseWelcome(welcomeBody)
	if err != nil {
		return nil, Welcome{}, fmt.Errorf("toy: WELCOME: %w", err)
	}

	// A client sends everything from its TUN to the one server.
	routes := []netip.Prefix{netip.PrefixFrom(netip.IPv4Unspecified(), 0)}
	s := NewSession(session, key, cfg.Server, routes)
	// The handshake consumed counters 1 and 2, so data starts at 3.
	s.counter.Store(2)

	logger.Printf("toy: session %d established as %v (assigned %v)", session, cfg.User, welcome.AssignedIP)
	return s, welcome, nil
}

// exchange sends req until a datagram of type want arrives, or the budget runs
// out. A REJECT is reported as the error it is rather than retried.
func exchange(ctx context.Context, conn *net.UDPConn, server *net.UDPAddr, req []byte,
	want MsgType, logger *vlog.Logger, what string) ([]byte, Header, error) {

	buf := make([]byte, 2048)
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, Header{}, err
		}
		if _, err := conn.WriteToUDP(req, server); err != nil {
			return nil, Header{}, fmt.Errorf("toy: sending %s: %w", what, err)
		}

		deadline := time.Now().Add(retryInterval)
		if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
			deadline = d
		}
		if err := conn.SetReadDeadline(deadline); err != nil {
			return nil, Header{}, err
		}

		for {
			n, _, err := conn.ReadFromUDP(buf)
			if err != nil {
				var netErr net.Error
				if errors.As(err, &netErr) && netErr.Timeout() {
					break // resend
				}
				return nil, Header{}, fmt.Errorf("toy: awaiting %v: %w", want, err)
			}

			h, body, err := ParseHeader(buf[:n])
			if err != nil {
				// Not ours, or malformed. Keep waiting rather than failing: a
				// shared port can carry anything.
				continue
			}
			switch h.Type {
			case want:
				_ = conn.SetReadDeadline(time.Time{})
				out := make([]byte, len(body))
				copy(out, body)
				return out, h, nil
			case MsgReject:
				reason, perr := ParseReject(body)
				if perr != nil {
					reason = "(unreadable)"
				}
				_ = conn.SetReadDeadline(time.Time{})
				if RejectIsCredential(reason) {
					return nil, Header{}, fmt.Errorf("%w: %s", ErrAuth, reason)
				}
				return nil, Header{}, fmt.Errorf("toy: server rejected the session: %s", reason)
			default:
				// A stale retransmission of an earlier step, most likely.
				continue
			}
		}
		logger.Printf("toy: no %v after %s (attempt %d/%d); resending %s",
			want, retryInterval, attempt, maxAttempts, what)
	}
	return nil, Header{}, fmt.Errorf("toy: no %v after %d attempts", want, maxAttempts)
}

// StartClient runs the handshake and then the data path over tun.
func StartClient(ctx context.Context, conn *net.UDPConn, tun *dataplane.TUN, cfg ClientConfig) (*Client, error) {
	session, welcome, err := Handshake(ctx, conn, cfg)
	if err != nil {
		return nil, err
	}

	logger := cfg.Logger

	send := func(pkt []byte, to *net.UDPAddr) {
		if _, err := conn.WriteToUDP(pkt, to); err != nil {
			logger.Printf("toy: send: %v", err)
		}
	}
	pump := dataplane.NewPump(tun, send, SessionOf, logger.Slog())
	pump.SetInnerMTU(int(welcome.MTU))
	pump.AddTunnel(session)

	c := &Client{
		conn:    conn,
		session: session,
		pump:    pump,
		tun:     tun,
		log:     logger,
		Welcome: welcome,
		done:    make(chan struct{}),
	}

	go pump.Run()
	go c.readLoop()
	go c.keepaliveLoop()
	return c, nil
}

// Session exposes the established session, for tests and callers that want to
// inspect it.
func (c *Client) Session() *Session { return c.session }

// IdleFor reports how long since the last authenticated inbound datagram (data
// or KEEPALIVE). Since the peer sends a KEEPALIVE every KeepaliveInterval, a
// value well beyond that means the peer is gone — the basis for a liveness
// probe.
func (c *Client) IdleFor() time.Duration { return c.pump.IdleFor() }

// readLoop carries inbound datagrams into the pump.
func (c *Client) readLoop() {
	buf := make([]byte, 65535)
	for {
		n, from, err := c.conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-c.done:
			default:
				c.log.Printf("toy: read: %v", err)
			}
			return
		}

		h, _, err := ParseHeader(buf[:n])
		if err != nil {
			continue
		}
		switch h.Type {
		case MsgData:
			pkt := make([]byte, n)
			copy(pkt, buf[:n])
			c.pump.HandleInbound(pkt, from)
		case MsgKeepalive:
			// Verified so a forged keepalive cannot hold a dead session open,
			// then discarded -- its only job was to arrive.
			if _, _, err := c.session.OpenAny(buf[:n]); err != nil {
				c.log.Printf("toy: bad keepalive: %v", err)
			}
		case MsgBye:
			// Unauthenticated, so advisory only. Acting on it would let anyone
			// who can send one datagram tear the tunnel down.
			c.log.Printf("toy: server sent BYE (advisory; ignoring)")
		}
	}
}

// keepaliveLoop holds the session and any NAT binding open.
func (c *Client) keepaliveLoop() {
	t := time.NewTicker(KeepaliveInterval)
	defer t.Stop()
	for {
		select {
		case <-c.done:
			return
		case <-t.C:
			pkt, err := c.session.Keepalive()
			if err != nil {
				c.log.Printf("toy: keepalive: %v", err)
				return
			}
			if _, err := c.conn.WriteToUDP(pkt, c.session.PeerAddr()); err != nil {
				c.log.Printf("toy: keepalive: %v", err)
			}
		}
	}
}

// Close tears the client down.
func (c *Client) Close() error {
	select {
	case <-c.done:
		return nil
	default:
		close(c.done)
	}
	// BYE is best-effort: the peer may be gone, and nothing depends on it.
	bye := AppendHeader(nil, Header{Type: MsgBye, Session: c.session.ID})
	_, _ = c.conn.WriteToUDP(bye, c.session.PeerAddr())

	c.pump.Close()
	err := c.conn.Close()
	if c.tun != nil {
		_ = c.tun.Close()
	}
	return err
}

// Done is closed when the client stops.
func (c *Client) Done() <-chan struct{} { return c.done }
