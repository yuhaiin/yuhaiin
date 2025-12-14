package resolver

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
	"github.com/miekg/dns"
)

func TestGroup(t *testing.T) {
	t.Run("all error", func(t *testing.T) {
		err1 := errors.New("err1")
		err2 := errors.New("err2")
		group, err := NewGroup(&mockDialer{err: err1}, &mockDialer{err: err2})
		assert.NoError(t, err)

		c := NewClient(Config{}, group)

		_, err = c.LookupIP(context.TODO(), "wwwww.google.com")
		assert.MustEqual(t, true, errors.Is(err, err1))
		assert.MustEqual(t, true, errors.Is(err, err2))
	})

	t.Run("rcode error", func(t *testing.T) {
		group, err := NewGroup(&mockDialer{rCode: dns.RcodeServerFailure}, &mockDialer{rCode: dns.RcodeNameError})
		assert.NoError(t, err)

		c := NewClient(Config{}, group)

		_, err = c.LookupIP(context.TODO(), "wwwww.google.com")

		var derr *net.DNSError
		assert.MustEqual(t, true, errors.As(err, &derr))
		assert.MustEqual(t, dns.RcodeToString[dns.RcodeServerFailure], derr.Err)
	})

	group, err := NewGroup(&mockDialer{err: errors.New("mock err")}, &mockDialer{})
	assert.NoError(t, err)

	c := NewClient(Config{}, group)

	ips, err := c.LookupIP(context.TODO(), "wwwww.google.com")
	assert.NoError(t, err)
	assert.MustEqual(t, 2, len(ips.A)+len(ips.AAAA))
}

type mockDialer struct {
	err   error
	rCode int
}

func (m *mockDialer) Do(ctx context.Context, req *Request) (dns.Msg, error) {
	if m.err != nil {
		time.Sleep(time.Millisecond * 200)
		return dns.Msg{}, m.err
	}
	var body dns.RR

	switch req.Question.Qtype {
	case dns.TypeA:
		body = &dns.A{A: net.IP{127, 0, 0, 1}}
	case dns.TypeAAAA:
		body = &dns.AAAA{AAAA: net.IP{127, 0, 0, 1}}
	}

	return dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:    req.ID,
			Rcode: m.rCode,
		},
		Question: []dns.Question{req.Question},
		Answer:   []dns.RR{body},
	}, nil
}
func (m *mockDialer) Close() error { return nil }
