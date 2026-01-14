package device

import (
	"fmt"
	"os"

	"github.com/Asutorufa/yuhaiin/pkg/net/netlink"
)

type Fd struct {
	fd  *os.File
	mtu int
}

var _ netlink.Tun = (*Fd)(nil)

func NewFd(fd int, mtu int) (*Fd, error) {
	return &Fd{
		fd:  os.NewFile(uintptr(fd), fmt.Sprintf("fd-%d", fd)),
		mtu: mtu,
	}, nil
}

func (d *Fd) Read(bufs [][]byte, sizes []int) (n int, err error) {
	n, err = d.fd.Read(bufs[0])
	if err != nil {
		return 0, err
	}
	sizes[0] = n
	return 1, nil
}

func (d *Fd) Write(bufs [][]byte) (int, error) {
	_, err := d.fd.Write(bufs[0])
	if err != nil {
		return 0, err
	}
	return 1, nil
}

func (d *Fd) Close() error   { return d.fd.Close() }
func (d *Fd) Offset() int    { return offset }
func (d *Fd) MTU() int       { return d.mtu }
func (d *Fd) BatchSize() int { return 1 }
