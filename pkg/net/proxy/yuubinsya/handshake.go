package yuubinsya

import (
	"context"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
)

// A dialing context does not interrupt I/O on an already established tunnel.
// Bound protocol setup even for callers without a deadline. This function owns
// conn during setup: canceled or failed handshakes discard it, while successful
// connections outlive the dialing context.
func runHandshake(ctx context.Context, conn net.Conn, handshake func() error) (err error) {
	ctx, cancel := context.WithTimeout(ctx, configuration.Timeout)
	// Register this first so it runs after the cleanup below (defer is LIFO).
	// Stop the close callback before our own cancel releases the timeout.
	defer cancel()
	if err := ctx.Err(); err != nil {
		_ = conn.Close()
		return err
	}
	done := make(chan struct{})
	// A deadline alone would not interrupt I/O on an early context cancellation.
	// Close handles both cancellation and timeout without depending on deadline
	// support in tunnel wrappers; an incomplete handshake is not reusable anyway.
	stop := context.AfterFunc(ctx, func() {
		_ = conn.Close()
		close(done)
	})
	defer func() {
		// A true result guarantees the callback will not run. A false result
		// means this callback has started, but stop does not wait for it to finish.
		// Wait explicitly so no close callback can outlive a successful return.
		if !stop() {
			<-done
		}
		// Cancellation can race with a successful final read/write. Report it
		// as a setup failure instead of returning a connection the callback closed;
		// preserve the context error rather than the resulting I/O close error.
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		if err != nil {
			_ = conn.Close()
		}
	}()
	return handshake()
}
