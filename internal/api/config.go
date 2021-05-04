package api

import (
	context "context"
	"log"

	"github.com/Asutorufa/yuhaiin/internal/app"
	config "github.com/Asutorufa/yuhaiin/internal/config"
	"google.golang.org/protobuf/types/known/emptypb"
)

var _ ConfigServer = (*Config)(nil)

type Config struct {
	UnimplementedConfigServer
	c           *config.Config
	connManager *app.ConnManager
}

func NewConfig(e *config.Config, ee *app.ConnManager) ConfigServer {
	return &Config{c: e, connManager: ee}
}

func (c *Config) GetConfig(cc context.Context, e *emptypb.Empty) (*config.Setting, error) {
	return c.c.Load(cc, e)
}

func (c *Config) SetConfig(cc context.Context, req *config.Setting) (*emptypb.Empty, error) {
	return c.c.Save(cc, req)
}

func (c *Config) ReimportRule(context.Context, *emptypb.Empty) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, c.c.ExecCommand("RefreshMapping")
}

func (c *Config) GetRate(_ *emptypb.Empty, srv Config_GetRateServer) error {
	ct, cancel := context.WithCancel(context.Background())
	r := newRate(ct)
	go c.connManager.Statistic(&emptypb.Empty{}, r)
	ctx := srv.Context()
	for {
		select {
		case <-ctx.Done():
			cancel()
			return ctx.Err()
		case s := <-r.data:
			err := srv.Send(&DaUaDrUr{
				Download: s.Download,
				Upload:   s.Upload,
				DownRate: s.DownloadRate,
				UpRate:   s.UploadRate,
			})
			if err != nil {
				log.Println(err)
			}
		}
	}
}

type rate struct {
	app.Connections_StatisticServer
	data    chan *app.RateResp
	context context.Context
}

func newRate(c context.Context) *rate {
	return &rate{
		data:    make(chan *app.RateResp, 3),
		context: c,
	}
}
func (r *rate) Send(s *app.RateResp) error {
	r.data <- s
	return nil
}

func (r *rate) Context() context.Context {
	return r.context
}
