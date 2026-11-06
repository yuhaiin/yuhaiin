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

func NewServer(server string, process netapi.Resolver) netapi.DNSAgent {
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
		d.complete(req, d.ctx.Err())
	}
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
				err = d.DoDatagram(d.ctx, &netapi.DNSRawRequest{
					Question:  packet,
					WriteBack: func(b []byte) error { _, err := listener.WriteTo(b, addr); return err },
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

				if err := d.handleTCP(context.TODO(), conn, false); err != nil {
					log.Error("handle dns tcp failed", "err", err)
				}
			}()
		}
	}()
}

func (d *dnsServer) DoStream(ctx context.Context, req *netapi.DNSStreamRequest) error {
	defer req.Conn.Close()
	return d.handleTCP(ctx, req.Conn, req.ForceFakeIP)
}

func (d *dnsServer) handleTCP(ctx context.Context, c net.Conn, forceFakeIP bool) error {
	var length uint16
	if err := binary.Read(c, binary.BigEndian, &length); err != nil {
		return fmt.Errorf("read dns length failed: %w", err)
	}

	data := pool.GetBytes(int(length))
	defer pool.PutBytes(data)

	_, err := io.ReadFull(c, data)
	if err != nil {
		return fmt.Errorf("dns server read data failed: %w", err)
	}

	return d.do(ctx, &doData{
		Question: data,
		WriteBack: func(b []byte) error {
			if err = pool.BinaryWriteUint16(c, binary.BigEndian, uint16(len(b))); err != nil {
				return fmt.Errorf("dns server write length failed: %w", err)
			}
			_, err = c.Write(b)
			return err
		},
		Stream:      true,
		ForceFakeIP: forceFakeIP,
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
}

func (d *dnsServer) do(ctx context.Context, req *doData) error {
	return d.doWithCache(ctx, req, false)
}

func (d *dnsServer) doWithCache(ctx context.Context, req *doData, cachedOnly bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	var parsed dns.Msg
	qmsg := req.query
	if qmsg == nil {
		// A retained packet/stream buffer stays alive until do returns.
		parsed.Data = req.Question
		if err := parsed.Unpack(); err != nil {
			return fmt.Errorf("dns server parse failed: %w", err)
		}
		qmsg = &parsed
	}

	if len(qmsg.Question) == 0 {
		return fmt.Errorf("question is empty")
	}

	question := netapi.DNSQuestionFromRR(qmsg.Question[0])

	var msg *dns.Msg
	var local bool
	if d.local != nil {
		msg, local = d.local.LocalResponse(question)
	}
	if local {
		metrics.Counter.AddDNSProcess(question.Name)
	}
	if !local {
		ctx, store := netapi.GetOrNewContext(ctx)
		store.ConnOptions().Resolver().SetUseFakeIP(req.ForceFakeIP)
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
		return err
	}
	msg.ID = qmsg.ID
	// Pack into a buffer owned by this request. Cached messages may share their
	// previous wire bytes, and callback consumers finish before this returns.
	wire := pool.GetBytes(msg.Len())
	defer pool.PutBytes(wire)
	msg.Data = wire
	if err := msg.Pack(); err != nil {
		return err
	}
	bytes := msg.Data

	if req.Stream || msg.Truncated {
		return req.WriteBack(bytes)
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
			return err
		}
		bytes = msg.Data
	}

	return req.WriteBack(bytes)
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
	req.request.Question.DecRef()
	d.outstanding.Add(-1)
	if req.request.Done != nil {
		req.request.Done(err)
	}
}

func (d *dnsServer) handle() {
	for {
		req, ok := d.reqBuffer.Pop()
		if !ok {
			return
		}
		metrics.Counter.ObserveDNSAdmissionWait("queue", time.Since(req.deadline.Add(-configuration.ResolverTimeout)))
		if err := req.ctx.Err(); err != nil {
			d.complete(req, err)
			continue
		}
		if !time.Now().Before(req.deadline) {
			d.complete(req, context.DeadlineExceeded)
			continue
		}
		if err := d.ctx.Err(); err != nil {
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
			err := d.do(ctx, &doData{prepared: true, query: req.query, Question: req.request.Question.GetPayload(), WriteBack: req.request.WriteBack, Stream: req.request.Stream, ForceFakeIP: req.request.ForceFakeIP})
			d.complete(req, err)
		}()
	}
}

func (d *dnsServer) DoDatagram(ctx context.Context, req *netapi.DNSRawRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := d.ctx.Err(); err != nil {
		return err
	}
	deadline := time.Now().Add(configuration.ResolverTimeout)
	// The parsed query is read-only and its wire data is the packet payload,
	// which the queued request retains (IncRef) until complete; no copy needed.
	query := &dns.Msg{Data: req.Question.GetPayload()}
	if err := query.Unpack(); err != nil {
		return fmt.Errorf("dns server parse failed: %w", err)
	}
	data := &doData{query: query, Question: req.Question.GetPayload(), WriteBack: req.WriteBack, Stream: req.Stream, ForceFakeIP: req.ForceFakeIP}
	err := d.doWithCache(ctx, data, true)
	if !errors.Is(err, netapi.ErrDNSCacheMiss) {
		if err == nil {
			metrics.Counter.AddDNSAdmissionResult("cache_hit")
			if req.Done != nil {
				req.Done(nil)
			}
		}
		return err
	}
	// Active queries plus the configured waiting budget is a hard bound on all
	// retained packets/goroutines, including duplicate requests waiting on a result.
	limit := d.udpSemaphore.Weight() + int64(max(0, configuration.MaxUDPUnprocessedPackets.Load()))
	if d.outstanding.Add(1) > limit {
		d.outstanding.Add(-1)
		metrics.Counter.AddReceiveUDPDroppedPacket()
		metrics.Counter.AddDNSAdmissionResult("budget_full")
		return errors.New("dns request budget is full")
	}
	queued := &queuedRequest{request: req, ctx: data.context, deadline: deadline, query: query}
	req.Question.IncRef()
	if !d.reqBuffer.Push(queued) {
		req.Question.DecRef()
		d.outstanding.Add(-1)
		metrics.Counter.AddReceiveUDPDroppedPacket()
		metrics.Counter.AddDNSAdmissionResult("queue_full")
		return errors.New("dns request buffer is full")
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
