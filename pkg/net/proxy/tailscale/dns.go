package tailscale

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/pipe"
)

type dnsQuery func(context.Context, []byte, string, netip.AddrPort) ([]byte, error)

type dnsPacket struct {
	ctx           context.Context
	cancel        context.CancelFunc
	query         dnsQuery
	server        netip.AddrPort
	replies       chan []byte
	readDeadline  pipe.PipeDeadline
	writeDeadline pipe.PipeDeadline
}

func newDNSPacket(ctx context.Context, query dnsQuery, server netip.AddrPort) *dnsPacket {
	ctx, cancel := context.WithCancel(ctx)
	return &dnsPacket{ctx: ctx, cancel: cancel, query: query, server: server,
		replies: make(chan []byte, 100), readDeadline: pipe.MakePipeDeadline(), writeDeadline: pipe.MakePipeDeadline()}
}

func (d *dnsPacket) Close() error {
	d.cancel()
	d.readDeadline.Set(time.Time{})
	d.writeDeadline.Set(time.Time{})
	return nil
}

func (d *dnsPacket) ReadFrom(b []byte) (int, net.Addr, error) {
	if d.ctx.Err() != nil {
		return 0, nil, net.ErrClosed
	}
	select {
	case <-d.ctx.Done():
		return 0, nil, net.ErrClosed
	case <-d.readDeadline.Wait():
		return 0, nil, os.ErrDeadlineExceeded
	case reply := <-d.replies:
		return copy(b, reply), net.UDPAddrFromAddrPort(d.server), nil
	}
}

func (d *dnsPacket) WriteTo(b []byte, addr net.Addr) (int, error) {
	if d.ctx.Err() != nil {
		return 0, net.ErrClosed
	}
	a, err := netapi.ParseSysAddr(addr)
	if err != nil {
		return 0, err
	}
	if a.IsFqdn() || a.(netapi.IPAddress).AddrPort() != d.server {
		return 0, errors.New("tailscale DNS socket only accepts its service address")
	}
	ctx, cancel, err := withWriteDeadline(d.ctx, &d.writeDeadline)
	if err != nil {
		return 0, err
	}
	defer cancel()
	deadline := d.writeDeadline.Wait()
	reply, err := d.query(ctx, b, "udp", netip.AddrPort{})
	if cause := context.Cause(ctx); cause != nil {
		if d.ctx.Err() != nil {
			return 0, net.ErrClosed
		}
		return 0, cause
	}
	if err != nil {
		return 0, err
	}
	select {
	case <-d.ctx.Done():
		return 0, net.ErrClosed
	case <-deadline:
		return 0, os.ErrDeadlineExceeded
	case d.replies <- reply:
		return len(b), nil
	}
}

func (d *dnsPacket) LocalAddr() net.Addr {
	if d.server.Addr().Is6() {
		return &net.UDPAddr{IP: net.IPv6unspecified}
	}
	return &net.UDPAddr{IP: net.IPv4zero}
}
func (d *dnsPacket) SetDeadline(t time.Time) error {
	if err := d.SetReadDeadline(t); err != nil {
		return err
	}
	return d.SetWriteDeadline(t)
}
func (d *dnsPacket) SetReadDeadline(t time.Time) error {
	if d.ctx.Err() != nil {
		return net.ErrClosed
	}
	d.readDeadline.Set(t)
	return nil
}
func (d *dnsPacket) SetWriteDeadline(t time.Time) error {
	if d.ctx.Err() != nil {
		return net.ErrClosed
	}
	d.writeDeadline.Set(t)
	return nil
}

// withWriteDeadline cancels work that can block before a virtual socket queues
// its datagram. Resetting or extending the deadline uses PipeDeadline's timer.
func withWriteDeadline(parent context.Context, deadline *pipe.PipeDeadline) (context.Context, context.CancelFunc, error) {
	wait := deadline.Wait()
	select {
	case <-wait:
		return nil, nil, os.ErrDeadlineExceeded
	default:
	}
	ctx, cancel := context.WithCancelCause(parent)
	go func() {
		select {
		case <-ctx.Done():
		case <-wait:
			cancel(os.ErrDeadlineExceeded)
		}
	}()
	return ctx, func() { cancel(nil) }, nil
}
