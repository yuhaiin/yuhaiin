package resolver

import (
	"context"
	"errors"
	"time"

	"github.com/miekg/dns"
)

type Group struct {
	dialers []Transport
}

func NewGroup(dialers ...Transport) (*Group, error) {
	if len(dialers) == 0 {
		return nil, errors.New("no dialer")
	}

	return &Group{dialers}, nil
}

func (g *Group) Do(ctx context.Context, req *Request) (dns.Msg, error) {
	count := len(g.dialers)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	type result struct {
		err  error
		resp dns.Msg
	}

	first := true

	var err error
	var fallbackMsg *dns.Msg
	ch := make(chan result)          // must be unbuffered
	failBoost := make(chan struct{}) // best effort send on dial failure

	go func() {
		for _, d := range g.dialers {
			if !first {
				timer := time.NewTimer(time.Millisecond * 100)
				select {
				case <-ctx.Done():
					timer.Stop()
					return
				case <-failBoost:
					timer.Stop()
				case <-timer.C:
				}
			}

			first = false

			go func(d Transport) {
				resp, er := d.Do(ctx, req)

				if er != nil {
					select {
					case failBoost <- struct{}{}:
					default:
					}
				}

				select {
				case ch <- result{er, resp}:
				case <-ctx.Done():
				}
			}(d)
		}
	}()

	for {
		select {
		case <-ctx.Done():
			if fallbackMsg != nil {
				return *fallbackMsg, nil
			}
			if err != nil {
				return dns.Msg{}, err
			}
			return dns.Msg{}, ctx.Err()
		case r := <-ch:
			count--

			if r.err == nil {
				msg := r.resp
				if msg.Rcode == dns.RcodeSuccess {
					return msg, nil
				}

				if fallbackMsg == nil {
					fallbackMsg = &msg
				}
			} else {
				err = errors.Join(err, r.err)
			}

			if count == 0 {
				if fallbackMsg != nil {
					return *fallbackMsg, nil
				}
				if err != nil {
					return dns.Msg{}, err
				}
			}
		}
	}
}

func (g *Group) Close() error {
	var err error
	for _, d := range g.dialers {
		if er := d.Close(); er != nil {
			err = errors.Join(err, er)
		}
	}
	return err
}
