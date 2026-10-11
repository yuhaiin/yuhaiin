package masque

// The client-side UDP forwarder.
//
// This is the half of CONNECT-UDP that does not look like a VPN. It binds a
// local UDP socket and, for each distinct local sender, opens one CONNECT-UDP
// flow to a fixed target through the proxy -- a forwarder, the way a DNS relay
// or a QUIC front end forwards. It produces no TUN and no client.Result, because
// there is no tunnel interface: a datagram in one side comes out the other.
//
// All flows share one QUIC connection to the proxy; each is its own HTTP/3
// request stream, which is exactly what HTTP/3's stream multiplexing is for. A
// flow is keyed by the local sender's address, so replies from the target find
// their way back to whoever sent to us -- the same association a NAT keeps.

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/xen0bit/veepin/internal/masque/http3"
	"github.com/xen0bit/veepin/internal/vlog"
	"golang.org/x/net/quic"
)

// udpFlowIdle is how long a local sender's flow is kept after its last datagram.
// A UDP forwarder has no close signal, so without this an idle flow would hold a
// request stream and a proxy socket open forever.
const udpFlowIdle = 2 * time.Minute

// UDPForwarder relays a local UDP socket to one target through CONNECT-UDP flows.
type UDPForwarder struct {
	h3        *http3.Conn
	local     *net.UDPConn
	host      string
	port      int
	authority string
	logger    *vlog.Logger

	mu     sync.Mutex
	flows  map[string]*udpFlow
	closed bool

	done chan struct{}
}

// udpFlow is one local sender's CONNECT-UDP flow.
type udpFlow struct {
	rs   *http3.RequestStream
	src  *net.UDPAddr
	seen time.Time
}

// NewUDPForwarderOverQUIC performs the HTTP/3 client setup over an established
// QUIC connection and returns a forwarder. It keeps the http3 types inside this
// package, so the public facade deals only in net and quic.
func NewUDPForwarderOverQUIC(ctx context.Context, qc *quic.Conn, local *net.UDPConn, host string, port int, authority string, logger *vlog.Logger) (*UDPForwarder, error) {
	h3conn, err := http3.Client(ctx, qc)
	if err != nil {
		return nil, err
	}
	return NewUDPForwarder(h3conn, local, host, port, authority, logger), nil
}

// NewUDPForwarder builds a forwarder over an established HTTP/3 connection to the
// proxy and a bound local socket, targeting host:port.
func NewUDPForwarder(h3conn *http3.Conn, local *net.UDPConn, host string, port int, authority string, logger *vlog.Logger) *UDPForwarder {
	if logger == nil {
		logger = vlog.Discard()
	}
	return &UDPForwarder{
		h3:        h3conn,
		local:     local,
		host:      host,
		port:      port,
		authority: authority,
		logger:    logger,
		flows:     map[string]*udpFlow{},
		done:      make(chan struct{}),
	}
}

// Run reads the local socket and forwards datagrams, until Close. It blocks.
func (f *UDPForwarder) Run() error {
	go f.expireLoop()

	buf := make([]byte, maxInnerPacket)
	// One encoder for this loop; every flow is written from here, so the shared
	// buffer has a single writer.
	var enc DatagramEncoder
	for {
		n, src, err := f.local.ReadFromUDP(buf)
		if err != nil {
			f.mu.Lock()
			closed := f.closed
			f.mu.Unlock()
			if closed {
				return nil
			}
			return fmt.Errorf("masque: local read: %w", err)
		}
		flow, err := f.flowFor(src)
		if err != nil {
			f.logger.Printf("masque: opening flow for %v: %v", src, err)
			continue
		}
		if _, err := flow.rs.Write(enc.Encode(buf[:n])); err != nil {
			f.logger.Printf("masque: forwarding from %v: %v", src, err)
			f.dropFlow(src.String())
		}
	}
}

// flowFor returns the flow for a local sender, opening a CONNECT-UDP request the
// first time one is seen. Opening happens inline, so the first datagram from a
// new sender pays one round trip; subsequent ones do not.
func (f *UDPForwarder) flowFor(src *net.UDPAddr) (*udpFlow, error) {
	key := src.String()

	f.mu.Lock()
	if flow, ok := f.flows[key]; ok {
		flow.seen = time.Now()
		f.mu.Unlock()
		return flow, nil
	}
	f.mu.Unlock()

	ctx := context.Background()
	path := ConnectUDPPath(f.host, f.port)
	rs, err := f.h3.OpenConnect(ctx, ConnectUDPHeaders(f.authority, path))
	if err != nil {
		return nil, err
	}
	resp, err := rs.ReadResponse()
	if err != nil {
		return nil, err
	}
	if status := fieldValue(resp, ":status"); status != "200" {
		_ = rs.Close()
		return nil, fmt.Errorf("proxy refused CONNECT-UDP: status %q", status)
	}

	flow := &udpFlow{rs: rs, src: src, seen: time.Now()}
	f.mu.Lock()
	// A concurrent caller may have won the race; keep the one already stored.
	if existing, ok := f.flows[key]; ok {
		f.mu.Unlock()
		_ = rs.Close()
		return existing, nil
	}
	f.flows[key] = flow
	f.mu.Unlock()

	go f.readFlow(flow)
	f.logger.Printf("masque: opened UDP flow for %v -> %s:%d", src, f.host, f.port)
	return flow, nil
}

// readFlow carries the target's replies back to the local sender.
func (f *UDPForwarder) readFlow(flow *udpFlow) {
	// One reader per flow goroutine; Value is valid only until the next Read,
	// and the UDP write below copies before then.
	var cr CapsuleReader
	for {
		capsule, err := cr.Read(flow.rs)
		if err != nil {
			f.dropFlow(flow.src.String())
			return
		}
		if capsule.Type != CapsuleDatagram {
			continue
		}
		payload, ok, err := DecodeDatagramPayload(capsule.Value)
		if err != nil || !ok {
			continue
		}
		if _, err := f.local.WriteToUDP(payload, flow.src); err != nil {
			f.dropFlow(flow.src.String())
			return
		}
	}
}

func (f *UDPForwarder) dropFlow(key string) {
	f.mu.Lock()
	flow, ok := f.flows[key]
	if ok {
		delete(f.flows, key)
	}
	f.mu.Unlock()
	if ok {
		_ = flow.rs.Close()
	}
}

// expireLoop closes flows that have gone quiet.
func (f *UDPForwarder) expireLoop() {
	t := time.NewTicker(udpFlowIdle / 2)
	defer t.Stop()
	for {
		select {
		case <-f.done:
			return
		case <-t.C:
			now := time.Now()
			var stale []*udpFlow
			f.mu.Lock()
			for key, flow := range f.flows {
				if now.Sub(flow.seen) > udpFlowIdle {
					stale = append(stale, flow)
					delete(f.flows, key)
				}
			}
			f.mu.Unlock()
			for _, flow := range stale {
				_ = flow.rs.Close()
				f.logger.Printf("masque: UDP flow for %v idle, closed", flow.src)
			}
		}
	}
}

// Close stops the forwarder and tears down every flow.
func (f *UDPForwarder) Close() error {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return nil
	}
	f.closed = true
	close(f.done)
	flows := f.flows
	f.flows = map[string]*udpFlow{}
	f.mu.Unlock()

	for _, flow := range flows {
		_ = flow.rs.Close()
	}
	_ = f.local.Close()
	return f.h3.Close()
}
