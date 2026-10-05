package statistics

import (
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
)

const sqlitePersistenceBatchSize = 32
const sqlitePersistenceRetryDelay = time.Second

// One reusable timer handles batching and failure retries. New events cannot
// bypass retry backoff, and there is no timer while the queue is idle.
func runPersistenceWorker(stop, trigger, done chan struct{}, delay time.Duration, full func() bool, flush func() error, name string) {
	defer close(done)
	var timer *time.Timer
	var timerC <-chan time.Time
	retryDelay := sqlitePersistenceRetryDelay
	retrying := false
	disarm := func() {
		if timer != nil {
			timer.Stop()
		}
		timerC = nil
	}
	defer disarm()
	arm := func(delay time.Duration) {
		if timer == nil {
			timer = time.NewTimer(delay)
		} else {
			timer.Reset(delay)
		}
		timerC = timer.C
	}
	drain := func() {
		disarm()
		if err := flush(); err != nil {
			log.Warn("batch sqlite persistence failed", "queue", name, "err", err)
			retrying = true
			arm(retryDelay)
			retryDelay = min(2*retryDelay, 30*time.Second)
			return
		}
		retrying = false
		retryDelay = sqlitePersistenceRetryDelay
	}
	for {
		select {
		case <-stop:
			return
		case <-trigger:
			if retrying {
				continue
			}
			if full() {
				drain()
			} else if timerC == nil {
				arm(delay)
			}
		case <-timerC:
			drain()
		}
	}
}
