package dialer

import (
	"sync/atomic"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/utils/atomicx"
)

var minDuration = time.Millisecond * 100
var maxDuration = time.Second * 2
var defaultDuration = time.Millisecond * 300

type Avg struct {
	ring    [100]*atomic.Pointer[time.Duration]
	current atomic.Int64
	count   atomic.Int64

	avg atomicx.Value[time.Duration]
}

func NewAvg() *Avg {
	x := &Avg{}

	x.avg.Store(defaultDuration)

	for i := range x.ring {
		x.ring[i] = atomicx.NewPointer(&defaultDuration)
	}

	return x
}

func (a *Avg) Push(n time.Duration) {
	i := a.current.Add(1) % 100

	a.ring[i].Store(&n)

	x := a.count.Add(1)
	if x > 25 && a.count.CompareAndSwap(x, 0) {
		a.avg.Store(a.Avg())
	}
}

func (a *Avg) Get() time.Duration {
	return a.avg.Load()
}

func (a *Avg) Avg() time.Duration {
	var max, min, sum time.Duration

	for _, u := range a.ring {
		v := *u.Load()
		if v > max || max == 0 {
			max = v
		}
		if v < min || min == 0 {
			min = v
		}

		sum += v
	}

	avg := (sum - min - max) / 98
	// The Connection Attempt Delay MUST have a lower bound, especially if
	// it is computed using historical data.  More specifically, a
	// subsequent connection MUST NOT be started within 10 milliseconds of
	// the previous attempt.  The recommended minimum value is 100
	// milliseconds, which is referred to as the "Minimum Connection Attempt
	// Delay".  This minimum value is required to avoid congestion collapse
	// in the presence of high packet-loss rates.  The Connection Attempt
	// Delay SHOULD have an upper bound, referred to as the "Maximum
	// Connection Attempt Delay".  The current recommended value is 2
	// seconds.

	if avg < minDuration {
		avg = minDuration
	}

	if avg > maxDuration {
		avg = maxDuration
	}

	return avg
}
