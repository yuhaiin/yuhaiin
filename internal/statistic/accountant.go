package statistic

import (
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/utils"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
)

type accountant struct {
	download, upload uint64

	clientCount int64

	started chan bool

	ig      idGenerater
	clients syncmap.SyncMap[int64, func(*statistic.RateResp) error]
	lock    sync.Mutex
}

func (c *accountant) AddDownload(n uint64) {
	atomic.AddUint64(&c.download, uint64(n))
}

func (c *accountant) AddUpload(n uint64) {
	atomic.AddUint64(&c.upload, uint64(n))
}

func (c *accountant) start() {
	c.lock.Lock()
	defer c.lock.Unlock()
	atomic.AddInt64(&c.clientCount, 1)
	if c.started != nil {
		select {
		case <-c.started:
		default:
			return
		}
	}

	c.started = make(chan bool)
	reduce := func(u uint64) string {
		r, unit := utils.ReducedUnit(float64(u))
		return fmt.Sprintf("%.2f%s", r, unit.String())
	}

	go func() {
		dw, up := atomic.LoadUint64(&c.download), atomic.LoadUint64(&c.upload)

		for {
			select {
			case <-time.After(time.Second):
			case _, ok := <-c.started:
				if !ok {
					log.Println("accountant stopped")
					return
				}
			}

			d, u := atomic.LoadUint64(&c.download), atomic.LoadUint64(&c.upload)

			c.clients.Range(
				func(key int64, value func(*statistic.RateResp) error) bool {
					data := &statistic.RateResp{
						Download:     reduce(d),
						Upload:       reduce(u),
						DownloadRate: reduce(d-dw) + "/S",
						UploadRate:   reduce(u-up) + "/S",
					}

					if err := value(data); err != nil {
						log.Println("accountant client error:", err)
					}

					return true
				})

			dw, up = d, u
		}
	}()
}

func (c *accountant) stop() {
	c.lock.Lock()
	defer c.lock.Unlock()
	atomic.AddInt64(&c.clientCount, -1)
	if atomic.LoadInt64(&c.clientCount) > 0 {
		return
	}

	log.Println("accountant stopping")

	if c.started != nil {
		close(c.started)
		c.started = nil
	}
}

func (c *accountant) AddClient(f func(*statistic.RateResp) error) (id int64) {
	id = c.ig.Generate()
	c.clients.Store(id, f)
	c.start()
	return
}

func (c *accountant) RemoveClient(id int64) {
	c.clients.Delete(id)
	c.stop()
}
