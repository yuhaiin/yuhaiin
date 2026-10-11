package client

import (
	"context"
	"sync"
	"time"
)

// Liveness — detecting a dead peer and tearing the tunnel down so it can be
// re-dialled — is a cross-protocol concern, so it lives here at the protocol-
// agnostic boundary rather than being re-solved in each protocol.
//
// The split is deliberate:
//
//   - Protocols that ride a *reliable* transport (TLS/TCP, or QUIC with its own
//     idle timeout — SSTP, SSH, MASQUE, Fortinet, SoftEther) already surface a
//     dead peer: the transport's read fails and the session's Wait returns. They
//     need nothing here.
//   - Protocols over a *datagram* transport with no built-in liveness (IKEv2/ESP,
//     WireGuard and AmneziaWG, OpenVPN-UDP, L2TP, Cisco IPsec, GlobalProtect's
//     ESP path, Ivanti's, AnyConnect's DTLS path, L2TPv3) can black-hole
//     silently — the socket stays "up" while nothing crosses. Those implement
//     Prober, and this package drives it.
//
// The second list was aspirational for three of the protocols on it. OpenVPN-UDP,
// L2TP and AnyConnect were named here as Prober implementations for a long time
// while implementing no Probe at all, and each had the *answering* half of a
// liveness exchange already built: OpenVPN sent pings and never timed out on
// silence, L2TP answered HELLO and never sent one, AnyConnect echoed DPD and
// never asked. Half a mechanism proves this end alive to a peer and learns
// nothing about the peer, which is the wrong half to have.
//
// Nebula is deliberately absent from both lists. It is a mesh, so one
// unreachable peer is not a dead session and closing the session would be the
// wrong response; its reachability probe lives in internal/nebula and drops the
// individual tunnel instead.
//
// A Session that implements Prober is wrapped automatically by Dial, so the
// capability is entirely abstracted away from callers: the CLI, the NM plugin
// and Go embedders all get dead-peer teardown without asking for it, and a
// protocol opts in with a single Probe method.

// Prober is an optional Session capability: an active liveness check. When a
// Session implements it, Dial monitors the session — probing on an interval and,
// after enough consecutive failures, closing it so Wait unblocks and the caller
// (or a supervising reconnect loop) can re-dial. A Session that rides a reliable
// transport need not implement Prober: its transport already surfaces death.
type Prober interface {
	// Probe actively verifies the peer is still reachable, returning nil if it
	// is. It should send whatever keepalive/DPD the protocol defines and wait
	// for the acknowledgement, honouring ctx's deadline. Probe must be safe to
	// call concurrently with the running data path, and must not block past ctx.
	Probe(ctx context.Context) error
}

// LivenessTuner is an optional companion to Prober: a Session that wants
// intervals other than the defaults returns them here. Zero values fall back to
// the defaults, so a protocol can override just the one field it cares about.
type LivenessTuner interface {
	LivenessConfig() LivenessConfig
}

// LivenessConfig parameterises the monitor. The defaults detect a dead peer in
// roughly a minute (Interval×MaxFailures) while tolerating transient loss.
type LivenessConfig struct {
	// Interval is the gap between probes once the last one settled.
	Interval time.Duration
	// Timeout bounds a single probe.
	Timeout time.Duration
	// MaxFailures is how many consecutive failed probes declare the peer dead.
	MaxFailures int
}

// DefaultLivenessConfig is used for a Prober that does not tune it, and fills in
// any zero field of one that does.
var DefaultLivenessConfig = LivenessConfig{
	Interval:    15 * time.Second,
	Timeout:     5 * time.Second,
	MaxFailures: 4,
}

// withDefaults replaces any zero field with the package default.
func (c LivenessConfig) withDefaults() LivenessConfig {
	if c.Interval <= 0 {
		c.Interval = DefaultLivenessConfig.Interval
	}
	if c.Timeout <= 0 {
		c.Timeout = DefaultLivenessConfig.Timeout
	}
	if c.MaxFailures <= 0 {
		c.MaxFailures = DefaultLivenessConfig.MaxFailures
	}
	return c
}

// monitored wraps a Session whose peer liveness is actively probed. It delegates
// Wait and Close to the underlying session and runs a monitor goroutine that
// closes the session after MaxFailures consecutive probe failures — which makes
// the underlying Wait return, exactly as a transport-detected death would.
type monitored struct {
	Session
	prober   Prober
	cfg      LivenessConfig
	stop     chan struct{}
	stopOnce sync.Once
}

// monitor wraps sess in a liveness monitor if it implements Prober, otherwise
// returns it unchanged. Dial calls this on every session it returns, so the
// behaviour is uniform and opt-in purely by capability.
func monitor(sess Session) Session {
	prober, ok := sess.(Prober)
	if !ok {
		return sess
	}
	cfg := DefaultLivenessConfig
	if t, ok := sess.(LivenessTuner); ok {
		cfg = t.LivenessConfig().withDefaults()
	}
	m := &monitored{
		Session: sess,
		prober:  prober,
		cfg:     cfg,
		stop:    make(chan struct{}),
	}
	go m.run()
	return m
}

// run probes on the configured interval, closing the session when MaxFailures
// probes fail in a row. A single success resets the counter, so isolated packet
// loss does not tear a healthy tunnel down.
func (m *monitored) run() {
	t := time.NewTicker(m.cfg.Interval)
	defer t.Stop()
	failures := 0
	for {
		select {
		case <-m.stop:
			return
		case <-t.C:
			ctx, cancel := context.WithTimeout(context.Background(), m.cfg.Timeout)
			err := m.prober.Probe(ctx)
			cancel()
			// A stop that raced with an in-flight probe means Close is tearing
			// the session down already; do not double-close or miscount.
			select {
			case <-m.stop:
				return
			default:
			}
			if err == nil {
				failures = 0
				continue
			}
			failures++
			if failures >= m.cfg.MaxFailures {
				// The peer is gone. Closing unblocks Wait; the monitor's own
				// stopper is tripped by Close so this goroutine then exits.
				_ = m.Session.Close()
				return
			}
		}
	}
}

// halt stops the monitor goroutine exactly once.
func (m *monitored) halt() { m.stopOnce.Do(func() { close(m.stop) }) }

// Wait blocks until the underlying session ends (on its own, or because the
// monitor closed it), then stops the monitor.
func (m *monitored) Wait(ctx context.Context) error {
	err := m.Session.Wait(ctx)
	m.halt()
	return err
}

// Close stops the monitor and tears the underlying session down.
func (m *monitored) Close() error {
	m.halt()
	return m.Session.Close()
}
