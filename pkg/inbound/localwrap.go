package inbound

import (
	"io"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/localwrap"
)

// StartLocalWrap connects a CLI-only endpoint to normal routing, DNS and policy.
// Its lifetime belongs to the application host, independently of saved listeners.
func (l *Inbound) StartLocalWrap(config localwrap.Config) (io.Closer, error) {
	config.FakeIPSource = l.fakeIPSource
	return localwrap.NewServer(config, &handlerWrap{id: "local-wrap", name: "Local wrap", handler: l})
}
