package lightweight

import (
	"testing"
	"time"
)

func TestACKOnlyWakesWriter(t *testing.T) {
	_, c, peer, _ := passiveWire(t, 100, 65535)
	if _, err := c.Write([]byte("payload")); err != nil {
		t.Fatal(err)
	}
	_ = peerPacket(t, peer)
	c.mu.Lock()
	defer c.mu.Unlock()
	read, write := watch(&c.changed), watch(&c.writeChanged)
	c.processAck(c.sndNxt, c.peerWindow, c.rcvNxt, tcpOptions{}, time.Now(), true)
	select {
	case <-read:
		t.Fatal("ACK woke reader without data")
	default:
	}
	select {
	case <-write:
	default:
		t.Fatal("ACK failed to wake writer")
	}
}

func TestTCPDeadlineNotifications(t *testing.T) {
	for _, mode := range []string{"read", "write", "both"} {
		t.Run(mode, func(t *testing.T) {
			c := &TCPConn{appClosed: true}
			read, write := watch(&c.changed), watch(&c.writeChanged)
			switch mode {
			case "read":
				_ = c.SetReadDeadline(time.Now())
			case "write":
				_ = c.SetWriteDeadline(time.Now())
			case "both":
				_ = c.SetDeadline(time.Now())
			}
			check := func(ch <-chan struct{}, want bool) {
				t.Helper()
				select {
				case <-ch:
					if !want {
						t.Fatal("wrong direction woke")
					}
				default:
					if want {
						t.Fatal("waiter stayed blocked")
					}
				}
			}
			check(read, mode != "write")
			check(write, mode != "read")
		})
	}
}
