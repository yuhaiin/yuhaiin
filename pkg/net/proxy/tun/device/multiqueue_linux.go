package device

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"sync"
	"sync/atomic"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netlink"
	wun "github.com/tailscale/wireguard-go/tun"
	"golang.org/x/sys/unix"
)

const (
	maxTUNReadQueues = 4
	tunVnetHdrLen    = 10
)

// multiQueueTUN keeps one native TUN device per kernel queue. Each reader owns
// a queue so packet processing remains ordered within that queue.
type multiQueueTUN struct {
	devices []wun.Device
	mtu     int
	offset  int
	next    atomic.Uint32

	closeOnce sync.Once
	closeErr  error
}

var _ netlink.Tun = (*multiQueueTUN)(nil)

func tunQueueCount() int {
	return min(max(runtime.GOMAXPROCS(0), 1), maxTUNReadQueues)
}

func openMultiQueueTUN(name string, mtu, queueCount int) (*multiQueueTUN, error) {
	if len(name) >= unix.IFNAMSIZ {
		return nil, fmt.Errorf("interface name too long: %s", name)
	}
	if queueCount < 1 {
		queueCount = 1
	}

	tuns := make([]wun.Device, 0, queueCount)

	for i := range queueCount {
		tun, err := openTUNQueue(name, mtu, true)
		if err != nil {
			if len(tuns) == 0 {
				// Older kernels may support TUN but not multi-queue attachments.
				// Keep the VNET header and batch path when only MULTI_QUEUE fails.
				tun, fallbackErr := openTUNQueue(name, mtu, false)
				if fallbackErr != nil {
					return nil, errors.Join(err, fallbackErr)
				}
				log.Warn("multi queue TUN unavailable; using one queue", "name", name, "err", err)
				tuns = append(tuns, tun)
				break
			}
			// Keep the queues that attached successfully. This permits operation
			// on kernels or devices that expose fewer queues than requested.
			log.Warn("attach TUN queue failed; using fewer queues", "requested", queueCount, "attached", i, "err", err)
			break
		}
		tuns = append(tuns, tun)
	}

	return &multiQueueTUN{
		devices: tuns,
		mtu:     mtu,
		offset:  tunVnetHdrLen,
	}, nil
}

func openTUNQueue(name string, mtu int, multiQueue bool) (wun.Device, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}

	ifr, err := unix.NewIfreq(name)
	if err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	flags := uint16(unix.IFF_TUN | unix.IFF_NO_PI | unix.IFF_VNET_HDR)
	if multiQueue {
		flags |= unix.IFF_MULTI_QUEUE
	}
	ifr.SetUint16(flags)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}

	file := os.NewFile(uintptr(fd), "/dev/net/tun")
	tun, err := wun.CreateTUNFromFile(file, mtu)
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	return tun, nil
}

func (t *multiQueueTUN) ReadQueueCount() int { return len(t.devices) }

func (t *multiQueueTUN) ReadQueue(queue int, bufs [][]byte, sizes []int) (int, error) {
	if queue < 0 || queue >= len(t.devices) {
		return 0, fmt.Errorf("tun queue index %d out of range", queue)
	}
	return t.devices[queue].Read(bufs, sizes, t.offset)
}

func (t *multiQueueTUN) Read(bufs [][]byte, sizes []int) (int, error) {
	queue := int((t.next.Add(1) - 1) % uint32(len(t.devices)))
	return t.ReadQueue(queue, bufs, sizes)
}

func (t *multiQueueTUN) Write(bufs [][]byte) (int, error) {
	queue := int((t.next.Add(1) - 1) % uint32(len(t.devices)))
	return t.devices[queue].Write(bufs, t.offset)
}

func (t *multiQueueTUN) BatchSize() int   { return t.devices[0].BatchSize() }
func (t *multiQueueTUN) Offset() int      { return t.offset }
func (t *multiQueueTUN) MTU() int         { return t.mtu }
func (t *multiQueueTUN) GSOEnabled() bool { return true }

func (t *multiQueueTUN) Close() error {
	t.closeOnce.Do(func() {
		for _, tun := range t.devices {
			t.closeErr = errors.Join(t.closeErr, tun.Close())
		}
	})
	return t.closeErr
}
