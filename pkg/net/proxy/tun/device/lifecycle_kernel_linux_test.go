//go:build linux && lightweight_kernel

package device

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
)

// Run in an isolated network namespace with CAP_NET_ADMIN, like the packet
// stack's kernel suite. Repeated link changes fill an undrained native event
// channel and leave its listener alive after the queue descriptors are closed.
func TestLinuxKernelDeviceLifecycle(t *testing.T) {
	for cycle := range 3 {
		t.Run(fmt.Sprint(cycle), func(t *testing.T) {
			d, err := openMultiQueueTUN("lifecycle0", 9000, 4)
			if err != nil {
				t.Fatal(err)
			}
			link, err := netlink.LinkByName("lifecycle0")
			if err != nil {
				_ = d.Close()
				t.Fatal(err)
			}
			var readers sync.WaitGroup
			for queue := range d.ReadQueueCount() {
				readers.Go(func() {
					bufs := make([][]byte, d.BatchSize())
					for i := range bufs {
						bufs[i] = make([]byte, 9000+d.Offset())
					}
					_, _ = d.ReadQueue(queue, bufs, make([]int, len(bufs)))
				})
			}
			for range 12 {
				if err := netlink.LinkSetUp(link); err != nil {
					t.Error(err)
					break
				}
				if err := netlink.LinkSetDown(link); err != nil {
					t.Error(err)
					break
				}
			}
			done := make(chan error, 1)
			go func() { err := d.Close(); readers.Wait(); done <- err }()
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("native TUN shutdown blocked")
			}
			for i, queue := range d.devices {
				select {
				case <-queue.eventsDone:
				default:
					t.Errorf("queue %d still has a native event listener", i)
				}
				if queue.slab != nil || queue.packets != nil {
					t.Errorf("queue %d retains read buffers", i)
				}
			}
		})
	}
}
