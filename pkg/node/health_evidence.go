package node

import (
	"context"
	"errors"
	"io"
	"net"
	"slices"
	"time"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/apernet/quic-go"
)

func cloneHealth(h contract.ChannelHealth) contract.ChannelHealth {
	h.Samples = slices.Clone(h.Samples)
	h.LatencySamples = slices.Clone(h.LatencySamples)
	return h
}

// Only explicit network/transport failures are evidence. Policy/quota errors
// and ordinary application errors remain visible to their owners and do not
// condemn a node. Dial timeouts count; caller cancellation does not.
func healthFailure(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || netapi.IsBlockError(err) {
		return false
	}
	if stream, ok := errors.AsType[*quic.StreamError](err); ok && stream.ErrorCode == 0 {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	_, ok := errors.AsType[net.Error](err)
	return ok
}

func (n *nodeCounters) remoteEvidence(tcp bool, sample contract.HealthSample, err error) {
	if err != nil && !healthFailure(err) {
		return
	}
	sample.OK = err == nil && sample.OK
	if e, ok := errors.AsType[net.Error](err); ok {
		sample.Timeout = e.Timeout()
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	h := &n.tcpHealth
	if !tcp {
		h = &n.udpHealth
	}
	if sample.At == 0 {
		sample.At = time.Now().UnixMilli()
	}
	h.Samples = append(h.Samples, sample)
	if len(h.Samples) > 64 {
		h.Samples = slices.Delete(h.Samples, 0, len(h.Samples)-64)
	}
	if sample.Kind == "https" || sample.Kind == "dns" {
		h.LatencySamples = append(h.LatencySamples, sample)
		if len(h.LatencySamples) > 64 {
			h.LatencySamples = slices.Delete(h.LatencySamples, 0, len(h.LatencySamples)-64)
		}
	}
	if sample.OK {
		h.ConsecutiveFailures = 0
		h.ConsecutiveSuccesses = min(h.ConsecutiveSuccesses+1, 64)
		if h.State != "unhealthy" || h.ConsecutiveSuccesses >= 2 {
			h.State = "healthy"
		}
	} else {
		h.ConsecutiveSuccesses = 0
		h.ConsecutiveFailures = min(h.ConsecutiveFailures+1, 64)
		h.State = "degraded"
		if h.ConsecutiveFailures >= 3 {
			h.State = "unhealthy"
		}
	}
}
