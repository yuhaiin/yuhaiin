package api

import (
	context "context"
	"fmt"
	"log"
	"time"

	"github.com/Asutorufa/yuhaiin/internal/app"
	config "github.com/Asutorufa/yuhaiin/internal/config"
	"github.com/Asutorufa/yuhaiin/pkg/net/utils"
	"google.golang.org/protobuf/types/known/emptypb"
)

var _ ConfigServer = (*Config)(nil)

type Config struct {
	UnimplementedConfigServer
	c        *config.Config
	entrance *app.ConnManager
}

func NewConfig(e *config.Config, ee *app.ConnManager) ConfigServer {
	return &Config{c: e, entrance: ee}
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
	fmt.Println("Start Send Flow Message to Client.")
	//TODO deprecated string
	da, ua := c.entrance.GetDownload(), c.entrance.GetUpload()
	var dr string
	var ur string
	ctx := srv.Context()
	for {
		dr = utils.ReducedUnitStr(float64(c.entrance.GetDownload()-da)) + "/S"
		ur = utils.ReducedUnitStr(float64(c.entrance.GetUpload()-ua)) + "/S"
		da, ua = c.entrance.GetDownload(), c.entrance.GetUpload()

		err := srv.Send(&DaUaDrUr{
			Download: utils.ReducedUnitStr(float64(da)),
			Upload:   utils.ReducedUnitStr(float64(ua)),
			DownRate: dr,
			UpRate:   ur,
		})
		if err != nil {
			log.Println(err)
		}
		select {
		case <-ctx.Done():
			fmt.Println("Client is Hidden, Close Stream.")
			return ctx.Err()
		case <-time.After(time.Second):
			continue
		}
	}
}
