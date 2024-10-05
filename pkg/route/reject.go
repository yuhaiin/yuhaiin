package route

import (
	"context"
	"sync/atomic"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	gc "github.com/Asutorufa/yuhaiin/pkg/protos/config/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type RejectHistoryObject struct {
	Protocol string
	Host     string
}

type RejectHistory struct {
	count atomic.Uint64
	store [1000]*gc.BlockHistory
}

func (h *RejectHistory) Push(ctx context.Context, protocol string, host string) {
	store := netapi.GetContext(ctx)

	i := h.count.Add(1) % 1000
	h.store[i] = &gc.BlockHistory{
		Protocol: protocol,
		Host:     host,
		Time:     timestamppb.Now(),
		Process: store.Process,
	}
}

func (h *RejectHistory) Get() []*gc.BlockHistory { return h.store[:min(h.count.Load(), 1000)] }
