package server

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/metrics"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/nat"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/pool"
	"github.com/Asutorufa/yuhaiin/pkg/utils/ringbuffer"
	"github.com/Asutorufa/yuhaiin/pkg/utils/semaphore"
	"github.com/Asutorufa/yuhaiin/pkg/utils/system"
)

type dnsServer struct {
	resolver netapi.Resolver
	local    netapi.LocalDNSResponder
	observer netapi.DNSObserver
	udp      net.PacketConn
	tcp      net.Listener

	ctx        context.Context
	cancel     context.CancelFunc
	notifyChan chan struct{}
	reqBuffer  *ringbuffer.RingBuffer[*queuedRequest]

	udpSemaphore semaphore.Semaphore
	outstanding  atomic.Int64
}

// Query wait is measured only by the singleflight owner, not by each duplicate.
type querySemaphore struct{ semaphore.Semaphore }

func (s *querySemaphore) Acquire(ctx context.Context, n int64) error {
	started := time.Now()
	err := s.Semaphore.Acquire(ctx, n)
	metrics.Counter.ObserveDNSAdmissionWait("upstream", time.Since(started))
	return err
}

// NewServer starts the DNS agent. An optional observer records the history of
// requests the agent receives on its own listeners; intercepted requests carry
// the trace their inbound started.
func NewServer(server string, process netapi.Resolver, observer ...netapi.DNSObserver) netapi.DNSAgent {
	ctx, cancel := context.WithCancel(context.Background())
	d := &dnsServer{
		ctx:          ctx,
		cancel:       cancel,
		resolver:     process,
		notifyChan:   make(chan struct{}, 1),
		udpSemaphore: &querySemaphore{semaphore.NewSemaphore(max(1, configuration.DNSProcessThread.Load()))},
		reqBuffer:    ringbuffer.NewRingBuffer[*queuedRequest](8, configuration.MaxUDPUnprocessedPackets.Load),
	}
	d.local, _ = process.(netapi.LocalDNSResponder)
	if len(observer) > 0 {
		d.observer = observer[0]
	}

	for range min(4, system.Procs) {
		go d.startHandleReqData()
	}

	if server == "" {
		log.Info("dns server is empty, skip to listen tcp and udp")
		return d
	}

	udp, err := dialer.ListenPacket(context.TODO(), "udp", server,
		dialer.WithListener())
	if err != nil {
		log.Error("dns udp server listen failed", "err", err)
	} else {
		d.udp = udp
		d.startUDP(udp)
	}

	tcp, err := dialer.ListenContext(context.TODO(), "tcp", server)
	if err != nil {
		log.Error("dns tcp server listen failed", "err", err)
	} else {
		d.tcp = tcp
		d.startTCP(tcp)
	}

	return d
}

func (d *dnsServer) Close() error {
	d.cancel()
	d.cancelQueued()

	var err error
	if d.udp != nil {
		if er := d.udp.Close(); er != nil {
			err = errors.Join(err, er)
		}
	}

	if d.tcp != nil {
		if er := d.tcp.Close(); er != nil {
			err = errors.Join(err, er)
		}
	}

	return err
}

func (d *dnsServer) cancelQueued() {
	for {
		req, ok := d.reqBuffer.Pop()
		if !ok {
			return
		}
		req.request.Trace.Fail(netapi.DNSOutcomeDropped, netapi.DNSStageAdmission, "shutdown", d.ctx.Err())
		d.complete(req, d.ctx.Err())
	}
}

func (d *dnsServer) begin(transport string) *netapi.DNSTrace {
	if d.observer == nil {
		return nil
	}
	return d.observer.BeginDNS(transport, netapi.DNSSourceLocal)
}

func (d *dnsServer) startUDP(listener net.PacketConn) {
	log.Info("new udp dns server", "host", listener.LocalAddr())

	for range min(4, system.Procs) {
		go func() {
			defer listener.Close()

			buf := pool.GetBytes(nat.MaxSegmentSize)
			defer pool.PutBytes(buf)

			for {
				n, addr, err := listener.ReadFrom(buf)
				if err != nil {
					// we just copy [Temporary] method from [net/http.Server.Serve]
					// so...
					if e, ok := err.(net.Error); ok && e.Temporary() { //nolint:staticcheck // Preserve listener retry semantics.
						continue
					}

					if !errors.Is(err, net.ErrClosed) {
						log.Error("dns udp server handle failed", "err", err)
					}
					return
				}

				packet := netapi.NewPacket(addr, netapi.EmptyAddr, pool.Clone(buf[:n]), nil)
				trace := d.begin("udp")
				trace.SetClient(addr)
				err = d.DoDatagram(d.ctx, &netapi.DNSRawRequest{
					Question: packet,
					Trace:    trace,
					WriteBack: func(b []byte) error {
						n, err := listener.WriteTo(b, addr)
						trace.AddSent(n)
						return err
					},
				})
				packet.DecRef()
				if err != nil {
					log.Debug("dns UDP request rejected", "err", err)
				}
			}
		}()
	}
}

func (d *dnsServer) startTCP(listener net.Listener) {
	go func() {
		defer listener.Close()

		log.Info("new tcp dns server", "host", listener.Addr())

		for {
			conn, err := listener.Accept()
			if err != nil {
				if e, ok := err.(net.Error); ok && e.Temporary() { //nolint:staticcheck // Preserve listener retry semantics.
					continue
				}
				log.Error("dns server accept failed", "err", err)
				return
			}

			go func() {
				defer conn.Close()

				trace := d.begin("tcp")
				trace.SetClient(conn.RemoteAddr())
				if err := d.handleTCP(context.TODO(), conn, false, trace); err != nil {
					log.Error("handle dns tcp failed", "err", err)
				}
			}()
		}
	}()
}

func (d *dnsServer) DoStream(ctx context.Context, req *netapi.DNSStreamRequest) error {
	defer req.Conn.Close()
	return d.handleTCP(ctx, req.Conn, req.ForceFakeIP, req.Trace)
}

// handleTCP serves one length-prefixed query and finishes its trace.
func (d *dnsServer) handleTCP(ctx context.Context, c net.Conn, forceFakeIP bool, trace *netapi.DNSTrace) (err error) {
	defer func() { trace.Finish(err) }()
	if trace != nil {
		trace.SetForceFakeIP(forceFakeIP)
		ctx = netapi.WithDNSTrace(ctx, trace)
	}
	var length uint16
	if err := binary.Read(c, binary.BigEndian, &length); err != nil {
		trace.Fail(netapi.DNSOutcomeMalformed, netapi.DNSStageIngress, "read_failed", err)
		return fmt.Errorf("read dns length failed: %w", err)
	}

	data := pool.GetBytes(int(length))
	defer pool.PutBytes(data)

	_, err = io.ReadFull(c, data)
	if err != nil {
		trace.Fail(netapi.DNSOutcomeMalformed, netapi.DNSStageIngress, "read_failed", err)
		return fmt.Errorf("dns server read data failed: %w", err)
	}

	return d.do(ctx, &doData{
		Question: data,
		WriteBack: func(b []byte) error {
			if err := pool.BinaryWriteUint16(c, binary.BigEndian, uint16(len(b))); err != nil {
				return fmt.Errorf("dns server write length failed: %w", err)
			}
			n, err := c.Write(b)
			trace.AddSent(n)
			return err
		},
		Stream:      true,
		ForceFakeIP: forceFakeIP,
		trace:       trace,
	})
}

func (d *dnsServer) HandleUDP(ctx context.Context, l net.PacketConn) error {
	buf := pool.GetBytes(nat.MaxSegmentSize)
	defer pool.PutBytes(buf)

	n, addr, err := l.ReadFrom(buf)
	if err != nil {
		return err
	}

	return d.do(ctx, &doData{
		Question: buf[:n],
		WriteBack: func(b []byte) error {
			_, err = l.WriteTo(b, addr)
			return err
		},
	})
}

type doData struct {
	context     context.Context
	prepared    bool
	query       *dns.Msg
	WriteBack   func([]byte) error
	Question    []byte
	Stream      bool
	ForceFakeIP bool
	trace       *netapi.DNSTrace
}

func (d *dnsServer) do(ctx context.Context, req *doData) error {
	return d.doWithCache(ctx, req, false)
}

func (d *dnsServer) doWithCache(ctx context.Context, req *doData, cachedOnly bool) error {
	trace := req.trace
	if err := ctx.Err(); err != nil {
		trace.Fail(netapi.ClassifyDNSError(err), netapi.DNSStageAdmission, "context_done", err)
		return err
	}
	var parsed dns.Msg
	qmsg := req.query
	if qmsg == nil {
		// A retained packet/stream buffer stays alive until do returns.
		parsed.Data = req.Question
		if err := parsed.Unpack(); err != nil {
			trace.SetQuery(nil, len(req.Question))
			trace.Fail(netapi.DNSOutcomeMalformed, netapi.DNSStageIngress, "parse_failed", err)
			return fmt.Errorf("dns server parse failed: %w", err)
		}
		qmsg = &parsed
		trace.SetQuery(qmsg, len(req.Question))
	}

	if len(qmsg.Question) == 0 {
		err := fmt.Errorf("question is empty")
		trace.Fail(netapi.DNSOutcomeMalformed, netapi.DNSStageIngress, "empty_question", err)
		return err
	}

	question := netapi.DNSQuestionFromRR(qmsg.Question[0])

	var msg *dns.Msg
	var local bool
	if d.local != nil {
		msg, local = d.local.LocalResponse(question)
	}
	if local {
		metrics.Counter.AddDNSProcess(question.Name)
		trace.SetSource(netapi.DNSResolutionCustom)
	}
	if !local {
		ctx, store := netapi.GetOrNewContext(ctx)
		store.ConnOptions().Resolver().SetUseFakeIP(req.ForceFakeIP)
		trace.BindContext(store)
		if !req.prepared {
			ctx = netapi.WithDNSQueryLimiter(ctx, d.udpSemaphore)
		}
		req.context = ctx
		var err error
		if cachedOnly {
			msg, err = netapi.CachedDNS(ctx, d.resolver, question)
		} else {
			var cancel context.CancelFunc
			if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > configuration.ResolverTimeout {
				ctx, cancel = context.WithTimeout(ctx, configuration.ResolverTimeout)
				defer cancel()
			}
			msg, err = netapi.RawDNS(ctx, d.resolver, question)
		}
		if err != nil {
			if cachedOnly {
				return err
			}
			return fmt.Errorf("do raw request (%v:%v) failed: %w", question.Name, question.Qtype, err)
		}
		if cachedOnly {
			metrics.Counter.AddDNSProcess(question.Name)
		}
	}

	if err := ctx.Err(); err != nil {
		trace.Fail(netapi.ClassifyDNSError(err), netapi.DNSStageDelivery, "context_done_before_write", err)
		return err
	}
	msg.ID = qmsg.ID
	trace.SetResponse(msg)
	// Pack into a buffer owned by this request. Cached messages may share their
	// previous wire bytes, and callback consumers finish before this returns.
	wire := pool.GetBytes(msg.Len())
	defer pool.PutBytes(wire)
	msg.Data = wire
	if err := msg.Pack(); err != nil {
		trace.Fail(netapi.DNSOutcomeInternal, netapi.DNSStagePack, "pack_failed", err)
		return err
	}
	bytes := msg.Data

	if req.Stream || msg.Truncated {
		trace.SetDelivery(len(bytes), false)
		return d.writeBack(req, bytes)
	}

	// https://www.rfc-editor.org/rfc/rfc1035
	// rfc1035 4.2.1
	//
	// Messages carried by UDP are restricted to 512 bytes (not counting the IP
	// or UDP headers).  Longer messages are truncated and the TC bit is set in
	// the header.
	//
	clientBufferSize := 512
	if qmsg.UDPSize > uint16(clientBufferSize) {
		clientBufferSize = int(qmsg.UDPSize)
	}

	if len(bytes) > clientBufferSize {
		msg.Truncated = true
		msg.Answer = nil
		msg.Ns = nil
		msg.Extra = nil
		if err := msg.Pack(); err != nil {
			trace.Fail(netapi.DNSOutcomeInternal, netapi.DNSStagePack, "pack_failed", err)
			return err
		}
		bytes = msg.Data
		trace.SetDelivery(len(bytes), true)
	} else {
		trace.SetDelivery(len(bytes), false)
	}

	return d.writeBack(req, bytes)
}

// writeBack separates producing a response from delivering it: a resolved
// answer that never reaches the client is a delivery failure.
func (d *dnsServer) writeBack(req *doData, b []byte) error {
	err := req.WriteBack(b)
	if err != nil {
		metrics.Counter.AddDNSResponseWriteError()
		reason := "write_failed"
		outcome := netapi.DNSOutcomeWriteError
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			reason, outcome = "context_done_before_write", netapi.ClassifyDNSError(err)
		}
		req.trace.Fail(outcome, netapi.DNSStageDelivery, reason, err)
	}
	return err
}

func (d *dnsServer) startHandleReqData() {
	for {
		select {
		case <-d.notifyChan:
			d.handle()
		case <-d.ctx.Done():
			return
		}
	}
}

// queuedRequest retains the caller's values, cancellation and the receipt-time
// deadline. No per-request goroutine or timer is needed for a cache hit.
type queuedRequest struct {
	query    *dns.Msg
	request  *netapi.DNSRawRequest
	ctx      context.Context
	deadline time.Time
}

func (d *dnsServer) complete(req *queuedRequest, err error) {
	if errors.Is(err, context.DeadlineExceeded) {
		metrics.Counter.AddDNSAdmissionResult("expired")
	} else if errors.Is(err, context.Canceled) {
		metrics.Counter.AddDNSAdmissionResult("canceled")
	}
	trace := req.request.Trace
	req.request.Question.DecRef()
	d.outstanding.Add(-1)
	if req.request.Done != nil {
		req.request.Done(err)
	}
	trace.Finish(err)
}

func (d *dnsServer) handle() {
	for {
		req, ok := d.reqBuffer.Pop()
		if !ok {
			return
		}
		wait := time.Since(req.deadline.Add(-configuration.ResolverTimeout))
		metrics.Counter.ObserveDNSAdmissionWait("queue", wait)
		trace := req.request.Trace
		trace.SetQueueWait(wait)
		if err := req.ctx.Err(); err != nil {
			outcome := netapi.ClassifyDNSError(err)
			if outcome == netapi.DNSOutcomeTimeout {
				outcome = netapi.DNSOutcomeDropped
			}
			trace.Fail(outcome, netapi.DNSStageAdmission, "canceled_in_queue", err)
			d.complete(req, err)
			continue
		}
		if !time.Now().Before(req.deadline) {
			trace.Fail(netapi.DNSOutcomeDropped, netapi.DNSStageAdmission, "expired", context.DeadlineExceeded)
			d.complete(req, context.DeadlineExceeded)
			continue
		}
		if err := d.ctx.Err(); err != nil {
			trace.Fail(netapi.DNSOutcomeDropped, netapi.DNSStageAdmission, "shutdown", err)
			d.complete(req, err)
			continue
		}
		// Bound retained packets separately from actual upstream query permits.
		// Singleflight waiters consume packet budget, but no upstream permit.
		go func() {
			ctx, cancel := context.WithDeadline(req.ctx, req.deadline)
			stop := context.AfterFunc(d.ctx, cancel)
			defer stop()
			defer cancel()
			if d.ctx.Err() != nil {
				cancel()
			}
			err := d.do(ctx, &doData{prepared: true, query: req.query, Question: req.request.Question.GetPayload(), WriteBack: req.request.WriteBack, Stream: req.request.Stream, ForceFakeIP: req.request.ForceFakeIP, trace: trace})
			d.complete(req, err)
		}()
	}
}

func (d *dnsServer) DoDatagram(ctx context.Context, req *netapi.DNSRawRequest) error {
	trace := req.Trace
	if err := ctx.Err(); err != nil {
		trace.Fail(netapi.ClassifyDNSError(err), netapi.DNSStageAdmission, "context_done", err)
		trace.Finish(err)
		return err
	}
	if err := d.ctx.Err(); err != nil {
		trace.Fail(netapi.DNSOutcomeDropped, netapi.DNSStageAdmission, "shutdown", err)
		trace.Finish(err)
		return err
	}
	deadline := time.Now().Add(configuration.ResolverTimeout)
	// The parsed query is read-only and its wire data is the packet payload,
	// which the queued request retains (IncRef) until complete; no copy needed.
	query := &dns.Msg{Data: req.Question.GetPayload()}
	if err := query.Unpack(); err != nil {
		trace.SetQuery(nil, len(req.Question.GetPayload()))
		trace.Fail(netapi.DNSOutcomeMalformed, netapi.DNSStageIngress, "parse_failed", err)
		trace.Finish(err)
		return fmt.Errorf("dns server parse failed: %w", err)
	}
	if trace != nil {
		trace.SetQuery(query, len(req.Question.GetPayload()))
		trace.SetForceFakeIP(req.ForceFakeIP)
		ctx = netapi.WithDNSTrace(ctx, trace)
	}
	data := &doData{query: query, Question: req.Question.GetPayload(), WriteBack: req.WriteBack, Stream: req.Stream, ForceFakeIP: req.ForceFakeIP, trace: trace}
	err := d.doWithCache(ctx, data, true)
	if !errors.Is(err, netapi.ErrDNSCacheMiss) {
		if err == nil {
			metrics.Counter.AddDNSAdmissionResult("cache_hit")
			trace.SetAdmission("cache_hit")
			if req.Done != nil {
				req.Done(nil)
			}
		}
		trace.Finish(err)
		return err
	}
	// Active queries plus the configured waiting budget is a hard bound on all
	// retained packets/goroutines, including duplicate requests waiting on a result.
	limit := d.udpSemaphore.Weight() + int64(max(0, configuration.MaxUDPUnprocessedPackets.Load()))
	if d.outstanding.Add(1) > limit {
		d.outstanding.Add(-1)
		metrics.Counter.AddReceiveUDPDroppedPacket()
		metrics.Counter.AddDNSAdmissionResult("budget_full")
		err := errors.New("dns request budget is full")
		trace.SetAdmission("budget_full")
		trace.Fail(netapi.DNSOutcomeDropped, netapi.DNSStageAdmission, "budget_full", err)
		trace.Finish(err)
		return err
	}
	queued := &queuedRequest{request: req, ctx: data.context, deadline: deadline, query: query}
	// Record before Push: a worker may complete the request immediately after.
	trace.SetAdmission("queued")
	req.Question.IncRef()
	if !d.reqBuffer.Push(queued) {
		req.Question.DecRef()
		d.outstanding.Add(-1)
		metrics.Counter.AddReceiveUDPDroppedPacket()
		metrics.Counter.AddDNSAdmissionResult("queue_full")
		err := errors.New("dns request buffer is full")
		trace.SetAdmission("queue_full")
		trace.Fail(netapi.DNSOutcomeDropped, netapi.DNSStageAdmission, "queue_full", err)
		trace.Finish(err)
		return err
	}
	metrics.Counter.AddDNSAdmissionResult("queued")
	// Close may have drained before Push. Exactly one pop owns completion.
	if d.ctx.Err() != nil {
		d.cancelQueued()
		return nil
	}
	select {
	case d.notifyChan <- struct{}{}:
	default:
	}
	return nil
}
