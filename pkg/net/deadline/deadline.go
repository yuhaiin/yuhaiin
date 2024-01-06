package deadline

import (
	"context"
	"time"
)

type Deadline struct {
	ctx    context.Context
	cancel context.CancelFunc

	deadline *time.Timer

	close func()
}

type opts struct {
	close func()

	wclose func()
	rclose func()
}

func WithClose(f func()) func(*opts) {
	return func(o *opts) {
		o.close = f
	}
}

func WithWriteClose(f func()) func(*opts) {
	return func(o *opts) {
		o.wclose = f
	}
}

func WithReadClose(f func()) func(*opts) {
	return func(o *opts) {
		o.rclose = f
	}
}

func New(os ...func(*opts)) *Deadline {
	o := &opts{}
	for _, f := range os {
		f(o)
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &Deadline{
		ctx:    ctx,
		cancel: cancel,
		close:  o.close,
	}
}

func (x *Deadline) Close() error {
	x.cancel()

	deadline := x.deadline

	if deadline != nil {
		deadline.Stop()
	}
	return nil
}

func (x *Deadline) SetDeadline(t time.Time) {
	until := time.Until(t)

	if !t.IsZero() && until <= 0 {
		_ = x.Close()
		if x.close != nil {
			x.close()
		}
		return
	}

	if x.deadline == nil {
		if !t.IsZero() {
			x.deadline = time.AfterFunc(until, func() {
				x.cancel()
				if x.close != nil {
					x.close()
				}
			})
		}
		return
	}

	if t.IsZero() {
		x.deadline.Stop()
	} else {
		x.deadline.Reset(until)
	}
}

func (x *Deadline) Context() context.Context { return x.ctx }

type PipeDeadline struct {
	w *Deadline
	r *Deadline
}

func NewPipe(os ...func(*opts)) *PipeDeadline {
	o := &opts{}
	for _, f := range os {
		f(o)
	}

	w := New(WithClose(o.wclose))
	r := New(WithClose(o.rclose))

	return &PipeDeadline{w: w, r: r}
}

func (x *PipeDeadline) Close() error {
	_ = x.r.Close()
	return x.w.Close()
}

func (x *PipeDeadline) SetDeadline(t time.Time) {
	x.w.SetDeadline(t)
	x.r.SetDeadline(t)
}

func (x *PipeDeadline) SetWriteDeadline(t time.Time) {
	x.w.SetDeadline(t)
}

func (x *PipeDeadline) SetReadDeadline(t time.Time) {
	x.r.SetDeadline(t)
}

func (x *PipeDeadline) WriteContext() context.Context { return x.w.ctx }

func (x *PipeDeadline) ReadContext() context.Context { return x.r.ctx }
