package dns

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
	"golang.org/x/net/dns/dnsmessage"
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
		group, err := NewGroup(&mockDialer{rCode: dnsmessage.RCodeServerFailure}, &mockDialer{rCode: dnsmessage.RCodeNameError})
		assert.NoError(t, err)

		c := NewClient(Config{}, group)

		_, err = c.LookupIP(context.TODO(), "wwwww.google.com")

		var derr *net.DNSError
		assert.MustEqual(t, true, errors.As(err, &derr))
		assert.MustEqual(t, dnsmessage.RCodeServerFailure.String(), derr.Err)
	})

	group, err := NewGroup(&mockDialer{err: errors.New("mock err")}, &mockDialer{})
	assert.NoError(t, err)

	c := NewClient(Config{}, group)

	ips, err := c.LookupIP(context.TODO(), "wwwww.google.com")
	assert.NoError(t, err)
	assert.MustEqual(t, 2, len(ips))
}

type mockDialer struct {
	err   error
	rCode dnsmessage.RCode
}

func (m *mockDialer) Do(ctx context.Context, req *Request) (Response, error) {
	if m.err != nil {
		time.Sleep(time.Millisecond * 200)
		return nil, m.err
	}
	var body dnsmessage.ResourceBody

	switch req.Question.Type {
	case dnsmessage.TypeA:
		body = &dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}}
	case dnsmessage.TypeAAAA:
		body = &dnsmessage.AAAAResource{AAAA: [16]byte{127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}}
	}

	return MsgResponse{
		Header: dnsmessage.Header{
			ID:    req.ID,
			RCode: m.rCode,
		},
		Questions: []dnsmessage.Question{req.Question},
		Answers: []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{Name: req.Question.Name, Class: dnsmessage.ClassINET, TTL: 600, Type: req.Question.Type},
			Body:   body,
		}},
	}, nil
}
func (m *mockDialer) Close() error { return nil }
