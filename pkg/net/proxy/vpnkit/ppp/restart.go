package ppp

import "time"

// The RFC 1661 Restart timer.
//
// A Configure-Request that draws no reply is resent every restartInterval, up to
// maxConfigure times, before the link is declared dead. veepin's other carriers
// (TLS under SSTP, an SSH channel) are reliable streams where a request cannot
// be lost, which is why the state machines here were originally driven purely by
// received packets. L2TP is the exception: its data channel is plain unreliable
// UDP inside ESP, and the very first Configure-Request routinely races the
// peer's pppd start-up and is dropped. Without a Restart timer both ends then
// wait forever — each having sent a request the other never saw.
//
// Retransmission reuses the request's original identifier, as RFC 1661 section
// 4.1 requires: a fresh identifier would read as a new request rather than a
// repeat of the outstanding one.
const (
	restartInterval = 2 * time.Second
	maxConfigure    = 10
)

// restartTimer tracks one control protocol's outstanding Configure-Request. The
// zero value is an unarmed timer. All of its fields are guarded by the owning
// session's mutex.
type restartTimer struct {
	timer *time.Timer
	tries int
}

// stop disarms the timer, which is what an incoming Configure-Ack means: the
// request it covered has been answered.
func (r *restartTimer) stop() {
	if r.timer != nil {
		r.timer.Stop()
		r.timer = nil
	}
	r.tries = 0
}

// alive resets the attempt counter without disarming. Any reply from the peer —
// including a Nak or a Reject, which answer a request without acknowledging it —
// proves the link is live, so the budget for the next request starts fresh.
func (r *restartTimer) alive() { r.tries = 0 }

// arm schedules resend to run under lock after restartInterval, and to keep
// running until stopped or the attempt budget is spent. expired is called
// instead once the budget runs out.
func (r *restartTimer) arm(lock func(func()), resend func(), expired func()) {
	if r.timer != nil {
		r.timer.Stop()
	}
	r.timer = time.AfterFunc(restartInterval, func() {
		lock(func() {
			// A stop that raced this firing leaves timer nil; the request it
			// covered is already answered, so there is nothing to resend.
			if r.timer == nil {
				return
			}
			r.tries++
			if r.tries >= maxConfigure {
				r.stop()
				expired()
				return
			}
			resend()
		})
	})
}
