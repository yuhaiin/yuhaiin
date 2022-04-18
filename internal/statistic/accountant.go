package statistic

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log/logasfmt"
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

	go func() {
		tmpD, tmpU := atomic.LoadUint64(&c.download), atomic.LoadUint64(&c.upload)

		for {
			select {
			case <-time.After(time.Second):
			case _, ok := <-c.started:
				if !ok {
					logasfmt.Println("accountant stopped")
					return
				}
			}

			d, u := atomic.LoadUint64(&c.download), atomic.LoadUint64(&c.upload)

			c.clients.Range(func(key int64, value func(*statistic.RateResp) error) bool {
				err := value(&statistic.RateResp{
					Download:     utils.ReducedUnitToString(float64(d)),
					Upload:       utils.ReducedUnitToString(float64(u)),
					DownloadRate: utils.ReducedUnitToString(float64(d-tmpD)) + "/S",
					UploadRate:   utils.ReducedUnitToString(float64(u-tmpU)) + "/S",
				})
				if err != nil {
					logasfmt.Println("accountant client error:", err)
				}
				return true
			})

			tmpD, tmpU = d, u
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

	logasfmt.Println("accountant stopping")

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
