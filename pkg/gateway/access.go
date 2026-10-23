package gateway

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

// A local respond action can block on a client that stops reading, without an
// outbound request observing context cancellation. Interrupt that write too.
// Join the callback before returning the ResponseWriter to net/http.
func interruptRevokedResponse(ctx context.Context, w http.ResponseWriter) func() {
	controller := http.NewResponseController(w)
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(done)
		if !errors.Is(context.Cause(ctx), netapi.ErrTrafficSessionClosed) {
			_ = controller.SetWriteDeadline(time.Now())
		}
	})
	return func() {
		if !stop() {
			<-done
			_ = controller.SetWriteDeadline(time.Time{})
		}
	}
}
