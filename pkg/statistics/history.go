package statistics

import (
	"context"
	"errors"
	"net"
	"sync/atomic"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	gs "github.com/Asutorufa/yuhaiin/pkg/protos/statistic/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type FailedHistory struct {
	count       atomic.Uint64
	store       [1000]*gs.FailedHistory
	dumpProcess bool
}

func (h *FailedHistory) Push(ctx context.Context, err error, protocol string, host netapi.Address) {
	if err == nil || netapi.IsBlockError(err) {
		return
	}

	store := netapi.GetContext(ctx)

	if !h.dumpProcess && store.Process != "" {
		h.dumpProcess = true
	}

	i := h.count.Add(1) % 1000

	de := &netapi.DialError{}
	if errors.As(err, &de) && de.Err != nil {
		err = de.Err
	}

	ne := &net.OpError{}
	if errors.As(err, &ne) {
		err = ne.Err
	}

	h.store[i] = &gs.FailedHistory{
		Protocol: protocol,
		Host:     getRealAddr(store, host),
		Error:    err.Error(),
		Time:     timestamppb.Now(),
		Process:  store.Process,
	}
}

func (h *FailedHistory) Get() *gs.FailedHistoryList {
	return &gs.FailedHistoryList{
		Objects:            h.store[:min(h.count.Load(), 1000)],
		DumpProcessEnabled: h.dumpProcess,
	}
}
