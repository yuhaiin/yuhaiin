package resolver

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"testing/synctest"

	"codeberg.org/miekg/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

func recoveryResponse(req *Request) *dns.Msg {
	return &dns.Msg{ID: req.ID, Response: true, Rcode: dns.RcodeSuccess,
		Answer: []dns.RR{&dns.A{Hdr: dns.Header{Name: req.Question.Name, Class: dns.ClassINET, TTL: 60}, Addr: netip.MustParseAddr("192.0.2.2")}},
	}
}

func TestUncachedQueryRecoversImmediately(t *testing.T) {
	for _, failure := range []error{errors.New("network unreachable"), context.DeadlineExceeded} {
		t.Run(failure.Error(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				attempts := 0
				online := false
				c := NewClient(Config{Name: "recovery-test"}, TransportFunc(func(_ context.Context, req *Request) (*dns.Msg, error) {
					attempts++
					if !online {
						return nil, failure
					}
					return recoveryResponse(req), nil
				})).(*client)
				defer c.Close()
				q := netapi.DNSQuestion{Name: "recovery.example.", Qtype: dns.TypeA}
				if _, err := c.Raw(t.Context(), q); !errors.Is(err, failure) {
					t.Fatalf("expected upstream failure, got %v", err)
				}
				online = true
				msg, err := c.Raw(t.Context(), q)
				if err != nil {
					t.Fatalf("recovered upstream still blocked by prior failure: %v (attempts=%d)", err, attempts)
				}
				if attempts != 2 || len(msg.Answer) != 1 {
					t.Fatalf("recovery did not query upstream: attempts=%d answer=%v", attempts, msg.Answer)
				}
			})
		})
	}
}

func TestBackgroundRefreshRecoversImmediately(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		attempts := 0
		online := false
		c := NewClient(Config{Name: "recovery-test"}, TransportFunc(func(_ context.Context, req *Request) (*dns.Msg, error) {
			attempts++
			if !online {
				return nil, errors.New("network unreachable")
			}
			return recoveryResponse(req), nil
		})).(*client)
		defer c.Close()
		q := expiredRefreshAnswer(c, "recovery.example.")
		lookup := func() *dns.Msg {
			t.Helper()
			msg, err := c.Raw(t.Context(), q)
			if err != nil || len(msg.Answer) != 1 {
				t.Fatalf("cached answer unavailable: msg=%v err=%v", msg, err)
			}
			synctest.Wait()
			return msg
		}
		lookup()
		online = true
		lookup() // Return stale data while retrying the recovered upstream.
		if attempts != 2 {
			t.Fatalf("recovered upstream refresh still blocked by prior failure: attempts=%d, want 2", attempts)
		}
		if got := lookup().Answer[0].(*dns.A).Addr; got != netip.MustParseAddr("192.0.2.2") {
			t.Fatalf("recovered upstream did not replace stale answer: %s", got)
		}
	})
}
