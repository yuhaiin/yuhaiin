package route

import (
	"context"
	"sync/atomic"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	gc "github.com/Asutorufa/yuhaiin/pkg/protos/config/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type RejectHistory struct {
	count       atomic.Uint64
	store       [1000]*gc.BlockHistory
	dumpProcess bool
}

func (h *RejectHistory) Push(ctx context.Context, protocol string, host string) {
	store := netapi.GetContext(ctx)

	if !h.dumpProcess && store.Process != "" {
		h.dumpProcess = true
	}

	i := h.count.Add(1) % 1000
	h.store[i] = &gc.BlockHistory{
		Protocol: protocol,
		Host:     host,
		Time:     timestamppb.Now(),
		Process:  store.Process,
	}
}

func (h *RejectHistory) Get() *gc.BlockHistoryList {
	return &gc.BlockHistoryList{
		Objects:            h.store[:min(h.count.Load(), 1000)],
		DumpProcessEnabled: h.dumpProcess,
	}
}
