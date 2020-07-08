package gui

import (
	"context"

	"github.com/Asutorufa/yuhaiin/api"
)

var (
	apiC api.ApiClient
)

func apiCtx() context.Context {

	//ctx, _ := context.WithTimeout(context.Background(), time.Second)
	return context.Background()
}
