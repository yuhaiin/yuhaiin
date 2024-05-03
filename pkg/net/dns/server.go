package dns

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/nat"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"github.com/Asutorufa/yuhaiin/pkg/utils/system"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/sync/semaphore"
)

type dnsServer struct {
	server      string
	resolver    netapi.Resolver
	listener    net.PacketConn
	tcpListener net.Listener

	sf *semaphore.Weighted
}

func NewServer(server string, process netapi.Resolver) netapi.DNSServer {
	d := &dnsServer{
		server:   server,
		resolver: process,
		sf:       semaphore.NewWeighted(200),
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
	if d.listener != nil {
		d.listener.Close()
	}
	if d.tcpListener != nil {
		d.tcpListener.Close()
	}

	return nil
}

func (d *dnsServer) startUDP() (err error) {
	d.listener, err = dialer.ListenPacket("udp", d.server)
	if err != nil {
		return fmt.Errorf("dns udp server listen failed: %w", err)
	}

	log.Info("new udp dns server", "host", d.server)

	for i := 0; i < system.Procs; i++ {
		go func() {
			defer d.Close()

			for {
				buf := pool.GetBytesBuffer(nat.MaxSegmentSize)
				_, addr, err := buf.ReadFromPacket(d.listener)
				if err != nil {
					buf.Free()

					if e, ok := err.(net.Error); ok && e.Temporary() {
						continue
					}

					if !errors.Is(err, net.ErrClosed) {
						log.Error("dns udp server handle failed", "err", err)
					}
					return
				}

				err = d.sf.Acquire(context.TODO(), 1)
				if err != nil {
					buf.Free()
					continue
				}

				go func() {
					defer d.sf.Release(1)
					err := d.Do(context.TODO(), &netapi.DNSRawRequest{
						Question: buf,
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
				}()

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

			if err := d.HandleTCP(context.TODO(), conn); err != nil {
				log.Error("handle dns tcp failed", "err", err)
			}
		}()
	}
}

type TCPKey struct{}

func (d *dnsServer) HandleTCP(ctx context.Context, c net.Conn) error {
	var length uint16
	if err := binary.Read(c, binary.BigEndian, &length); err != nil {
		return fmt.Errorf("read dns length failed: %w", err)
	}

	data := pool.GetBytesBuffer(int(length))

	_, err := io.ReadFull(c, data.Bytes())
	if err != nil {
		return fmt.Errorf("dns server read data failed: %w", err)
	}

	return d.Do(ctx, &netapi.DNSRawRequest{
		Question: data,
		WriteBack: func(b []byte) error {
			if err = binary.Write(c, binary.BigEndian, uint16(len(b))); err != nil {
				return fmt.Errorf("dns server write length failed: %w", err)
			}
			_, err = c.Write(b)
			return err
		},
		Stream: true,
	})
}

func (d *dnsServer) HandleUDP(ctx context.Context, l net.PacketConn) error {
	buf := pool.GetBytesBuffer(nat.MaxSegmentSize)

	_, addr, err := buf.ReadFromPacket(l)
	if err != nil {
		return err
	}

	return d.Do(context.TODO(), &netapi.DNSRawRequest{
		Question: buf,
		WriteBack: func(b []byte) error {
			_, err = l.WriteTo(b, addr)
			return err
		},
	})
}

func (d *dnsServer) Do(ctx context.Context, req *netapi.DNSRawRequest) error {
	ctx, cancel := context.WithTimeout(ctx, time.Second*10)
	defer cancel()

	defer req.Question.Free()

	var parse dnsmessage.Parser
	header, err := parse.Start(req.Question.Bytes())
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
