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

func NewDnsServer(server string, process netapi.Resolver) netapi.DNSHandler {
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
				n, addr, err := d.listener.ReadFrom(buf.Bytes())
				if err != nil {
					pool.PutBytesBuffer(buf)

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
					pool.PutBytesBuffer(buf)
					continue
				}

				buf.ResetSize(0, n)

				go func() {
					defer d.sf.Release(1)
					err := d.Do(context.TODO(), buf, func(b []byte) error {
						if _, err = d.listener.WriteTo(b, addr); err != nil {
							return fmt.Errorf("write dns response to client failed: %w", err)
						}
						return nil
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

	return d.Do(ctx, data, func(b []byte) error {
		if err = binary.Write(c, binary.BigEndian, uint16(len(b))); err != nil {
			return fmt.Errorf("dns server write length failed: %w", err)
		}
		_, err = c.Write(b)
		return err
	})
}

func (d *dnsServer) HandleUDP(ctx context.Context, l net.PacketConn) error {
	buf := pool.GetBytesBuffer(nat.MaxSegmentSize)

	n, addr, err := l.ReadFrom(buf.Bytes())
	if err != nil {
		return err
	}

	buf.ResetSize(0, n)

	return d.Do(context.TODO(), buf, func(b []byte) error {
		_, err = l.WriteTo(b, addr)
		return err
	})
}

func (d *dnsServer) Do(ctx context.Context, b *pool.Bytes, writeBack func([]byte) error) error {
	ctx, cancel := context.WithTimeout(ctx, time.Second*10)
	defer cancel()

	defer pool.PutBytesBuffer(b)

	var parse dnsmessage.Parser
	header, err := parse.Start(b.Bytes())
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

	return writeBack(bytes)
}
