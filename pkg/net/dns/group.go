package dns

import (
	"context"
	"errors"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type Group struct {
	dialers []Dialer
}

func NewGroup(dialers ...Dialer) (*Group, error) {
	if len(dialers) == 0 {
		return nil, errors.New("no dialer")
	}

	return &Group{dialers}, nil
}

func (g *Group) Do(ctx context.Context, req *Request) (Response, error) {
	count := len(g.dialers)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	type result struct {
		resp Response
		err  error
	}

	first := true

	var err error
	var fallbackMsg *dnsmessage.Message
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

			go func(d Dialer) {
				resp, er := d.Do(ctx, req)

				if er != nil {
					select {
					case failBoost <- struct{}{}:
					default:
					}
				}

				select {
				case ch <- result{resp, er}:
				case <-ctx.Done():
					if er == nil {
						resp.Release()
					}
				}
			}(d)
		}
	}()

	for {
		select {
		case <-ctx.Done():
			if fallbackMsg != nil {
				return MsgResponse(*fallbackMsg), nil
			}
			if err != nil {
				return nil, err
			}
			return nil, ctx.Err()
		case r := <-ch:
			count--

			if r.err == nil {
				msg, er := r.resp.Msg()
				r.resp.Release()
				if er == nil {
					if msg.RCode == dnsmessage.RCodeSuccess {
						return r.resp, nil
					}

					if fallbackMsg == nil {
						fallbackMsg = &msg
					}
				} else {
					err = errors.Join(err, er)
				}
			} else {
				err = errors.Join(err, r.err)
			}

			if count == 0 {
				if fallbackMsg != nil {
					return MsgResponse(*fallbackMsg), nil
				}
				if err != nil {
					return nil, err
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
