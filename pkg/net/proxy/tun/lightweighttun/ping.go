package lightweighttun

import (
	"context"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

// Keep the prepared routing path dormant. Enabling it later requires changing
// both ICMP interception and the bounded worker startup through this one gate.
const forwardPing = false
const pingWorkers = 8

func (s *server) pingLoop() {
	for {
		request, err := s.stack.ReceivePing(context.Background())
		if err != nil {
			return
		}
		source, destination := request.Source, request.Destination
		local := destination.IsLoopback()
		if destination.Is4() {
			local = local || s.options.V4Contains(destination) || !s.options.V4Contains(source)
		} else {
			local = local || s.options.V6Contains(destination) || !s.options.V6Contains(source)
		}
		if local {
			if err := request.Reply(nil); err != nil {
				log.Debug("lightweight local ping reply failed", "err", err)
			}
			continue
		}
		s.options.HandlePing(&netapi.PingMeta{
			Source:      netapi.ParseNetipAddr("udp", source, 0),
			Destination: netapi.ParseNetipAddr("udp", destination, 0),
			WriteBack:   func(_ uint64, err error) error { return request.Reply(err) },
		})
	}
}
