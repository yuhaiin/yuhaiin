package simplehttp

import (
	"io"
	"net/http"
	"runtime"
	"strings"
	"unsafe"

	tps "github.com/Asutorufa/yuhaiin/internal/http/templates"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	grpcconfig "github.com/Asutorufa/yuhaiin/pkg/protos/config/grpc"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/emptypb"
)

type configHandler struct {
	emptyHTTP
	cf grpcconfig.ConfigDaoServer
}

func (cc *configHandler) Get(w http.ResponseWriter, r *http.Request) error {
	c, err := cc.cf.Load(r.Context(), &emptypb.Empty{})
	if err != nil {
		return err
	}

	data, err := protojson.MarshalOptions{Indent: "  ", EmitUnpopulated: true}.Marshal(c)
	if err != nil {
		return err
	}

	return TPS.BodyExecute(w, map[string]any{
		"Config": unsafe.String(&data[0], len(data)),
		"GOOS":   strings.ToLower(runtime.GOOS),
	}, tps.CONFIG)
}

func (c *configHandler) Post(w http.ResponseWriter, r *http.Request) error {
	data, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}

	config := &config.Setting{}
	err = protojson.UnmarshalOptions{DiscardUnknown: true}.Unmarshal(data, config)
	if err != nil {
		return err
	}

	_, err = c.cf.Save(r.Context(), config)
	if err != nil {
		return err
	}

	w.Write(nil)
	return nil
}
