package statistics

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
	download, upload atomic.Uint64

	clientCount atomic.Int64

	started chan struct{}

	ig      IDGenerator
	clients syncmap.SyncMap[int64, func(*statistic.RateResp) error]
	lock    sync.Mutex
}

func (c *accountant) AddDownload(n uint64) { c.download.Add(n) }
func (c *accountant) AddUpload(n uint64)   { c.upload.Add(n) }

func (c *accountant) start() {
	c.lock.Lock()
	defer c.lock.Unlock()

	c.clientCount.Add(1)
	select {
	case <-c.started:
	default:
		if c.started != nil {
			return
		}
	}

	c.started = make(chan struct{})

	reduce := func(u uint64) string {
		r, unit := utils.ReducedUnit(float64(u))
		return fmt.Sprintf("%.2f%s", r, unit.String())
	}

	go func() {
		dw, up := c.download.Load(), c.upload.Load()

		for {
			select {
			case <-time.After(time.Second):
			case _, ok := <-c.started:
				if !ok {
					log.Println("accountant stopped")
					return
				}
			}

			d, u := c.download.Load(), c.upload.Load()

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
	c.clientCount.Add(-1)
	if c.clientCount.Load() > 0 {
		return
	}

	log.Println("accountant stopping")

	if c.started != nil {
		close(c.started)
	}
}

func (c *accountant) AddClient(f func(*statistic.RateResp) error) (id int64) {
	id = c.ig.Generate()
	c.clients.Store(id, f)
	c.start()
	return
}

func (c *accountant) RemoveClient(id int64) {
	if _, ok := c.clients.LoadAndDelete(id); ok {
		c.stop()
	}
}
