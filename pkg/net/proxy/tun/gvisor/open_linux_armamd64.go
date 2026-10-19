//go:build (linux && amd64) || (linux && arm64)

// github.com/google/gvisor/pkg/tcpip/link/fdbased/mmap.go only support linux,amd64 linux,arm64
// so add build tag for fdbased
package gvisor

import (
	"fmt"
	"runtime"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netlink"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tun/device"
	vnetlink "github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const (
	// tunTxQueueLength gives the userspace stack room to drain bursty traffic.
	tunTxQueueLength = 10000
	maxTunQueues     = 4
)

type fdBasedEndpoint struct {
	stack.LinkEndpoint
	fds      []int
	closeOne sync.Once
}

func (e *fdBasedEndpoint) Close() {
	e.closeOne.Do(func() {
		e.Attach(nil)
		e.LinkEndpoint.Close()
		closeTunFDs(e.fds)
	})
}

func openTunQueue(name string, flags uint16) (int, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}

	ifr, err := unix.NewIfreq(name)
	if err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	ifr.SetUint16(flags)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}

	return fd, nil
}

func openTunQueues(name string) ([]int, bool, error) {
	queueCount := min(runtime.GOMAXPROCS(0), maxTunQueues)
	flags := uint16(unix.IFF_TUN | unix.IFF_NO_PI | unix.IFF_MULTI_QUEUE)
	fds := make([]int, 0, queueCount)

	for range queueCount {
		fd, err := openTunQueue(name, flags)
		if err != nil {
			if len(fds) > 0 {
				break
			}

			// Keep compatibility with kernels or pre-existing devices that do not
			// support TUN multiqueue.
			fd, fallbackErr := openTunQueue(name, uint16(unix.IFF_TUN|unix.IFF_NO_PI))
			if fallbackErr != nil {
				return nil, false, fmt.Errorf("open tun queue: %w (single-queue fallback: %v)", err, fallbackErr)
			}
			return []int{fd}, false, nil
		}
		fds = append(fds, fd)
	}

	return fds, true, nil
}

func closeTunFDs(fds []int) {
	for _, fd := range fds {
		_ = unix.Close(fd)
	}
}

func resizeTunQueue(fd int) (attached bool, err error) {
	// Linux sizes the userspace receive ring when a TUN queue is attached.
	// Reattach after setting tx_queue_len so the FD uses the requested capacity.
	ifr, err := unix.NewIfreq("")
	if err != nil {
		return true, err
	}
	ifr.SetUint16(unix.IFF_DETACH_QUEUE)
	if err := unix.IoctlIfreq(fd, unix.TUNSETQUEUE, ifr); err != nil {
		return true, fmt.Errorf("detach tun queue: %w", err)
	}

	ifr.SetUint16(unix.IFF_ATTACH_QUEUE)
	if err := unix.IoctlIfreq(fd, unix.TUNSETQUEUE, ifr); err != nil {
		return false, fmt.Errorf("reattach tun queue: %w", err)
	}
	return true, nil
}

func init() {
	openFD = func(sc netlink.TunScheme, mtu int) (stack.LinkEndpoint, error) {
		switch sc.Scheme {
		case "fd":
			// fdbased.New borrows its FDs. Keep Android's original FD open
			// independently, and release only our duplicate on endpoint.Close.
			owned, err := device.DuplicateBorrowedFD(sc.Fd)
			if err != nil {
				return nil, fmt.Errorf("duplicate fdbased TUN fd: %w", err)
			}
			endpoint, err := fdbased.New(&fdbased.Options{
				FDs:               []int{owned},
				MTU:               uint32(mtu),
				RXChecksumOffload: true,
			})
			if err != nil {
				_ = unix.Close(owned)
				return nil, err
			}
			return &fdBasedEndpoint{LinkEndpoint: endpoint, fds: []int{owned}}, nil
		case "tun":
			// fdbased current not support gso, so open new tun direct instead of wireguard
			//
			// https://github.com/google/gvisor/blob/ef1ca17e584230d9c70f31ac991549adede09839/pkg/tcpip/link/fdbased/endpoint.go#L323
			// check is socket, can't enable gso
			fds, multiQueue, err := openTunQueues(sc.Name)
			if err != nil {
				return nil, fmt.Errorf("create tun failed: %w", err)
			}

			tunLink, err := vnetlink.LinkByName(sc.Name)
			if err != nil {
				closeTunFDs(fds)
				return nil, err
			}
			txQueueLengthSet := true
			if err := vnetlink.LinkSetTxQLen(tunLink, tunTxQueueLength); err != nil {
				log.Warn("set tun tx queue length failed; using existing queue length", "name", sc.Name, "err", err)
				txQueueLengthSet = false
			}

			if err := vnetlink.LinkSetMTU(tunLink, mtu); err != nil {
				if currentMTU := tunLink.Attrs().MTU; currentMTU != mtu {
					closeTunFDs(fds)
					return nil, fmt.Errorf("set tun mtu: %w", err)
				}
				log.Debug("set tun mtu failed; interface already has requested mtu", "name", sc.Name, "mtu", mtu, "err", err)
			}

			if multiQueue && txQueueLengthSet {
				resizedFDs := make([]int, 0, len(fds))
				var lastResizeErr error
				for _, fd := range fds {
					attached, err := resizeTunQueue(fd)
					if err != nil {
						log.Warn("resize tun receive queue failed", "name", sc.Name, "err", err)
						lastResizeErr = err
						if !attached {
							_ = unix.Close(fd)
							continue
						}
					}
					resizedFDs = append(resizedFDs, fd)
				}
				if len(resizedFDs) == 0 {
					return nil, fmt.Errorf("resize tun receive queue: no attached queues remain: %w", lastResizeErr)
				}
				fds = resizedFDs
			}

			endpoint, err := fdbased.New(&fdbased.Options{
				FDs:                   fds,
				MTU:                   uint32(mtu),
				RXChecksumOffload:     true,
				MaxSyscallHeaderBytes: 0x00,
			})
			if err != nil {
				closeTunFDs(fds)
				return nil, err
			}
			return &fdBasedEndpoint{LinkEndpoint: endpoint, fds: fds}, nil

		default:
			return nil, fmt.Errorf("invalid tun: %v", sc)
		}
	}
}
