package hysteria2

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
)

func benchmarkHappyEyeballsTargets(n int) []*net.UDPAddr {
	targets := make([]*net.UDPAddr, 0, n)
	for i := range n {
		if i%2 == 0 {
			targets = append(targets, &net.UDPAddr{IP: net.IPv4(192, 0, 2, byte(i)), Port: 443})
		} else {
			ip := make(net.IP, net.IPv6len)
			copy(ip, net.ParseIP("2001:db8::"))
			ip[15] = byte(i)
			targets = append(targets, &net.UDPAddr{IP: ip, Port: 443})
		}
	}
	return targets
}

// BenchmarkHappyEyeballsFailover exercises the scheduler when every attempt
// but the last fails immediately (RFC 8305 failure acceleration), with a
// previously successful endpoint that is no longer in the candidate list.
func BenchmarkHappyEyeballsFailover(b *testing.B) {
	errUnreachable := errors.New("unreachable")
	for _, n := range []int{2, 16, 64} {
		targets := benchmarkHappyEyeballsTargets(n)
		last := targets[n-1]
		preferred := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 443}
		b.Run(fmt.Sprintf("targets=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				ch := make(chan happyEyeballsBatch, 1)
				ch <- happyEyeballsBatch{addrs: targets}
				close(ch)
				conn, _, err := raceHappyEyeballsv2(context.Background(), ch, preferred, false, func(_ context.Context, remote *net.UDPAddr) (*happyEyeballsTestConn, error) {
					if remote != last {
						return nil, errUnreachable
					}
					return &happyEyeballsTestConn{}, nil
				})
				if err != nil {
					b.Fatal(err)
				}
				_ = conn.Close()
			}
		})
	}
}
