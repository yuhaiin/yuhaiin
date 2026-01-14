package batch

import (
	"errors"
	"log/slog"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netlink"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/rawfile"
	"gvisor.dev/gvisor/pkg/tcpip/link/stopfd"
)

var _ netlink.Tun = (*Tun)(nil)

type Tun struct {
	stopfd.StopFD
	fd  int
	mtu int
}

const (
	// MaxMsgsPerRecv is the maximum number of packets we want to retrieve
	// in a single RecvMMsg call.
	MaxMsgsPerRecv = 8
)

func NewTun(fd int, mtu int) (*Tun, error) {
	stopFD, err := stopfd.New()
	if err != nil {
		return nil, err
	}

	return &Tun{
		StopFD: stopFD,
		fd:     fd,
		mtu:    mtu,
	}, nil
}

func (d *Tun) Read(bufs [][]byte, sizes []int) (n int, err error) {
	mmsgHdrs := make([]rawfile.MMsgHdr, len(bufs))
	for k := range bufs {
		mmsgHdrs[k].Len = 0
		mmsgHdrs[k].Msg.Iov = &unix.Iovec{
			Base: &bufs[k][0],
			Len:  uint64(len(bufs[k])),
		}
		mmsgHdrs[k].Msg.SetIovlen(1)
	}

	nMsgs, errno := rawfile.BlockingRecvMMsgUntilStopped(d.EFD, d.fd, mmsgHdrs)

	log.Info("linux tun read batch", slog.Int("n", nMsgs), "err", errno)

	if errno != 0 {
		return 0, errno
	}
	if nMsgs == -1 {
		return 0, errors.New("stopfd")
	}

	for i := 0; i < nMsgs; i++ {
		sizes[i] = int(mmsgHdrs[i].Len)
	}

	return nMsgs, nil
}

func (d *Tun) Write(bufs [][]byte) (int, error) {
	mmsgHdrs := make([]rawfile.MMsgHdr, len(bufs))

	for k := range bufs {
		mmsgHdrs[k].Len = 0
		mmsgHdrs[k].Msg.Iov = &unix.Iovec{
			Base: &bufs[k][0],
			Len:  uint64(len(bufs[k])),
		}
		mmsgHdrs[k].Msg.SetIovlen(1)
	}

	for len(mmsgHdrs) > 0 {
		sent, errno := rawfile.NonBlockingSendMMsg(d.fd, mmsgHdrs)
		if errno != 0 {
			return sent, errno
		}
		mmsgHdrs = mmsgHdrs[sent:]
	}

	return len(bufs), nil
}

func (d *Tun) Close() error {
	d.StopFD.Stop()
	return nil
}

func (d *Tun) Offset() int {
	return 0
}

func (d *Tun) MTU() int {
	return d.mtu
}

func (d *Tun) BatchSize() int {
	return MaxMsgsPerRecv
}
