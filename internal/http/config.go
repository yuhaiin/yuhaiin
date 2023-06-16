package simplehttp

import (
	"io"
	"net/http"

	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	grpcconfig "github.com/Asutorufa/yuhaiin/pkg/protos/config/grpc"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/emptypb"
)

type configHandler struct {
	cf grpcconfig.ConfigServiceServer
}

func (cc *configHandler) Config(w http.ResponseWriter, r *http.Request) error {
	c, err := cc.cf.Load(r.Context(), &emptypb.Empty{})
	if err != nil {
		return err
	}

	data, err := protojson.MarshalOptions{Indent: "  ", EmitUnpopulated: true}.Marshal(c)
	if err != nil {
		return err
	}

	_, err = w.Write(data)
	return err
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
