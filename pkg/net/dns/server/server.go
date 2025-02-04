package server

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/nat"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"github.com/Asutorufa/yuhaiin/pkg/utils/system"
	"golang.org/x/net/dns/dnsmessage"
)

type dnsServer struct {
	resolver    netapi.Resolver
	listener    net.PacketConn
	tcpListener net.Listener
	server      string

	ctx     context.Context
	cancel  context.CancelFunc
	reqChan chan *netapi.DNSRawRequest
}

func NewServer(server string, process netapi.Resolver) netapi.DNSServer {
	ctx, cancel := context.WithCancel(context.Background())
	d := &dnsServer{
		ctx:      ctx,
		cancel:   cancel,
		server:   server,
		resolver: process,
		reqChan:  make(chan *netapi.DNSRawRequest, 100),
	}

	for range configuration.DNSProcessThread.Load() {
		go d.startHandleReqData()
	}

	if server == "" {
		log.Info("dns server is empty, skip to listen tcp and udp")
		return d
	}

	if err := d.startUDP(); err != nil {
		log.Error("start udp dns server failed", slog.Any("err", err))
	}

	go func() {
		if err := d.startTCP(); err != nil {
			log.Error("start tcp dns server failed", slog.Any("err", err))
		}
	}()

	return d
}

func (d *dnsServer) Close() error {
	d.cancel()

	if d.listener != nil {
		d.listener.Close()
	}
	if d.tcpListener != nil {
		d.tcpListener.Close()
	}

	return nil
}

func (d *dnsServer) startUDP() (err error) {
	d.listener, err = dialer.ListenPacket(context.TODO(), "udp", d.server, dialer.WithListener(), dialer.WithTryUpgradeToBatch())
	if err != nil {
		return fmt.Errorf("dns udp server listen failed: %w", err)
	}

	log.Info("new udp dns server", "host", d.server)

	for range system.Procs {
		go func() {
			defer d.Close()

			buf := pool.GetBytes(nat.MaxSegmentSize)
			defer pool.PutBytes(buf)

			for {
				n, addr, err := d.listener.ReadFrom(buf)
				if err != nil {
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
							if _, err = d.listener.WriteTo(b, addr); err != nil {
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

	return nil
}

func (d *dnsServer) startTCP() (err error) {
	defer d.Close()

	d.tcpListener, err = dialer.ListenContext(context.TODO(), "tcp", d.server)
	if err != nil {
		return fmt.Errorf("dns tcp server listen failed: %w", err)
	}

	log.Info("new tcp dns server", "host", d.server)

	for {
		conn, err := d.tcpListener.Accept()
		if err != nil {
			if e, ok := err.(net.Error); ok && e.Temporary() {
				continue
			}
			return fmt.Errorf("dns server accept failed: %w", err)
		}

		go func() {
			defer conn.Close()

			if err := d.handleTCP(context.TODO(), conn, false); err != nil {
				log.Error("handle dns tcp failed", "err", err)
			}
		}()
	}
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
	ctx, cancel := context.WithTimeout(ctx, configuration.Timeout)
	defer cancel()

	if req.ForceFakeIP {
		ctx = context.WithValue(ctx, netapi.ForceFakeIPKey{}, true)
	}

	var parse dnsmessage.Parser
	header, err := parse.Start(req.Question)
	if err != nil {
		return fmt.Errorf("dns server parse failed: %w", err)
	}

	question, err := parse.Question()
	if err != nil {
		return fmt.Errorf("dns server parse failed: %w", err)
	}

	msg, err := d.resolver.Raw(ctx, question)
	if err != nil {
		return fmt.Errorf("do raw request (%v:%v) failed: %w", question.Name, question.Type, err)
	}

	msg.ID = header.ID

	respBuf := pool.GetBytes(pool.DefaultSize)
	defer pool.PutBytes(respBuf)

	bytes, err := msg.AppendPack(respBuf[:0])
	if err != nil {
		return err
	}

	if req.Stream || msg.Truncated {
		return req.WriteBack(bytes)
	}

	// TODO
	// https://www.rfc-editor.org/rfc/rfc1035
	// rfc1035 4.2.1
	//
	// Messages carried by UDP are restricted to 512 bytes (not counting the IP
	// or UDP headers).  Longer messages are truncated and the TC bit is set in
	// the header.
	//

	_ = parse.SkipAllQuestions()
	_ = parse.SkipAllAnswers()
	_ = parse.SkipAllAuthorities()

	clientBufferSize := 512
	for {
		additional, err := parse.Additional()
		if err != nil {
			break
		}

		// rfc 6891
		// Values lower than 512 MUST be treated as equal to 512.
		if additional.Header.Type == dnsmessage.TypeOPT && additional.Header.Class > 512 {
			clientBufferSize = int(additional.Header.Class)
		}
	}

	if len(bytes) > clientBufferSize {
		msg.Truncated = true
		msg.Answers = nil
		msg.Authorities = nil
		msg.Additionals = nil
		bytes, err = msg.AppendPack(respBuf[:0])
		if err != nil {
			return err
		}
	}

	return req.WriteBack(bytes)
}

func (d *dnsServer) startHandleReqData() {
	for {
		select {
		case req := <-d.reqChan:
			err := d.do(d.ctx, &doData{
				Question:    req.Question.Payload,
				WriteBack:   req.WriteBack,
				Stream:      req.Stream,
				ForceFakeIP: req.ForceFakeIP,
			})
			req.Question.DecRef()
			if err != nil {
				log.Error("handle dns request failed", "err", err)
			}
		case <-d.ctx.Done():
			return
		}
	}
}

func (d *dnsServer) Do(ctx context.Context, req *netapi.DNSRawRequest) error {
	req.Question.IncRef()
	select {
	case d.reqChan <- req:
		return nil
	case <-ctx.Done():
		req.Question.DecRef()
		return ctx.Err()
	case <-d.ctx.Done():
		req.Question.DecRef()
		return d.ctx.Err()
	}
}
