package server

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/nat"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"github.com/Asutorufa/yuhaiin/pkg/utils/ringbuffer"
	"github.com/Asutorufa/yuhaiin/pkg/utils/system"
	"github.com/miekg/dns"
)

type dnsServer struct {
	resolver netapi.Resolver
	udp      net.PacketConn
	tcp      net.Listener

	ctx        context.Context
	cancel     context.CancelFunc
	notifyChan chan struct{}
	reqBuffer  ringbuffer.RingBuffer[*netapi.DNSRawRequest]
	mu         sync.Mutex
}

func NewServer(server string, process netapi.Resolver) netapi.DNSServer {
	ctx, cancel := context.WithCancel(context.Background())
	d := &dnsServer{
		ctx:        ctx,
		cancel:     cancel,
		resolver:   process,
		notifyChan: make(chan struct{}, 1),
	}

	d.reqBuffer.Init(200)

	for range configuration.DNSProcessThread.Load() {
		go d.startHandleReqData()
	}

	if server == "" {
		log.Info("dns server is empty, skip to listen tcp and udp")
		return d
	}

	udp, err := dialer.ListenPacket(context.TODO(), "udp", server,
		dialer.WithListener(), dialer.WithTryUpgradeToBatch())
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
					if e, ok := err.(net.Error); ok && e.Temporary() {
						continue
					}

					if !errors.Is(err, net.ErrClosed) {
						log.Error("dns udp server handle failed", "err", err)
					}
					return
				}

				go func(b []byte) {
					defer pool.PutBytes(b)

					err := d.do(context.TODO(), &doData{
						Question: b,
						WriteBack: func(b []byte) error {
							if _, err = listener.WriteTo(b, addr); err != nil {
								return fmt.Errorf("write dns response to client failed: %w", err)
							}
							return nil
						},
					})
					if err != nil {
						log.Error("dns server handle data failed", slog.Any("err", err))
					}
				}(pool.Clone(buf[:n]))
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
				if e, ok := err.(net.Error); ok && e.Temporary() {
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

	return d.do(context.TODO(), &doData{
		Question: buf[:n],
		WriteBack: func(b []byte) error {
			_, err = l.WriteTo(b, addr)
			return err
		},
	})
}

type doData struct {
	WriteBack   func([]byte) error
	Question    []byte
	Stream      bool
	ForceFakeIP bool
}

func (d *dnsServer) do(ctx context.Context, req *doData) error {
	ctx, cancel := context.WithTimeout(ctx, configuration.ResolverTimeout)
	defer cancel()

	if req.ForceFakeIP {
		ctx = context.WithValue(ctx, netapi.ForceFakeIPKey{}, true)
	}

	var qmsg dns.Msg
	if err := qmsg.Unpack(req.Question); err != nil {
		return fmt.Errorf("dns server parse failed: %w", err)
	}

	if len(qmsg.Question) == 0 {
		return fmt.Errorf("question is empty")
	}

	question := qmsg.Question[0]

	msg, err := d.resolver.Raw(ctx, question)
	if err != nil {
		return fmt.Errorf("do raw request (%v:%v) failed: %w", question.Name, dns.Type(question.Qtype), err)
	}

	msg.Id = qmsg.Id

	respBuf := pool.GetBytes(pool.DefaultSize)
	defer pool.PutBytes(respBuf)

	bytes, err := msg.PackBuffer(respBuf[:0])
	if err != nil {
		return err
	}

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
	for _, additional := range msg.Extra {
		// rfc 6891
		// Values lower than 512 MUST be treated as equal to 512.
		if additional.Header().Rrtype == dns.TypeOPT && additional.Header().Class > 512 {
			clientBufferSize = int(additional.Header().Class)
		}
	}

	if len(bytes) > clientBufferSize {
		msg.Truncated = true
		msg.Answer = nil
		msg.Ns = nil
		msg.Extra = nil
		bytes, err = msg.PackBuffer(respBuf[:0])
		if err != nil {
			return err
		}
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

func (d *dnsServer) handle() {
	d.mu.Lock()
	nums := d.reqBuffer.Len()
	if nums == 0 {
		d.mu.Unlock()
		return
	}

	var hasMorePackets bool

	for i := range nums {
		if i > 0 {
			d.mu.Lock()
		}

		hasMorePackets = !d.reqBuffer.Empty()
		if !hasMorePackets {
			d.mu.Unlock()
			return
		}

		req := d.reqBuffer.PopFront()
		d.mu.Unlock()

		err := d.do(d.ctx, &doData{
			Question:    req.Question.GetPayload(),
			WriteBack:   req.WriteBack,
			Stream:      req.Stream,
			ForceFakeIP: req.ForceFakeIP,
		})
		if err != nil {
			log.Error("handle dns request failed", "err", err, "len", len(req.Question.GetPayload()))
		}
		req.Question.DecRef()
	}
}

func (d *dnsServer) Do(ctx context.Context, req *netapi.DNSRawRequest) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-d.ctx.Done():
		return d.ctx.Err()
	default:
		d.mu.Lock()
		if d.reqBuffer.Len() >= configuration.MaxUDPUnprocessedPackets.Load() {
			d.mu.Unlock()
			return fmt.Errorf("dns request buffer is full")
		}

		req.Question.IncRef()
		d.reqBuffer.PushBack(req)
		d.mu.Unlock()

		select {
		case d.notifyChan <- struct{}{}:
		default:
		}
	}

	return nil
}
