package dialer

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/metrics"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

func DialHappyEyeballsv1(ctx context.Context, addr netapi.Address) (net.Conn, error) {
	c, err := dialHappyEyeballs(ctx, addr)
	if err != nil {
		metrics.Counter.AddTCPDialFailed(addr.String())
	}
	return c, err
}

func dialHappyEyeballs(ctx context.Context, addr netapi.Address) (net.Conn, error) {
	if !addr.IsFqdn() {
		return DialContext(ctx, "tcp", addr.String())
	}

	ips, err := LookupIP(ctx, addr)
	if err != nil {
		return nil, err
	}

	lastIP, ok := happyEyeballsCache.Load(addr.Hostname())

	tcpAddress := make([]*net.TCPAddr, 0, ips.Len())
	for ip := range ips.Iter() {
		if ok && lastIP.Equal(ip) && len(tcpAddress) > 0 {
			tmp := tcpAddress[0]
			tcpAddress[0] = &net.TCPAddr{IP: ip, Port: tmp.Port}
			tcpAddress = append(tcpAddress, tmp)
		} else {
			tcpAddress = append(tcpAddress, &net.TCPAddr{IP: ip, Port: int(addr.Port())})
		}
	}

	conn, err := DialHappyEyeballs(ctx, tcpAddress)
	if err != nil {
		return nil, err
	}

	connAddr, ok := conn.RemoteAddr().(*net.TCPAddr)
	if ok {
		happyEyeballsCache.Add(addr.Hostname(), connAddr.IP)
	}

	return conn, nil
}

// DialHappyEyeballs is a function that implements Happy Eyeballs algorithm for IPv4 and IPv6 addresses.
// It divides given TCP addresses into primaries and fallbacks and then calls DialParallel function.
//
// It takes a context and a slice of TCP addresses as input and returns a net.Conn and an error.
//
// https://www.rfc-editor.org/rfc/rfc8305
func DialHappyEyeballs(ctx context.Context, ips []*net.TCPAddr) (net.Conn, error) {
	// Divide TCP addresses into primaries and fallbacks based on their IP version.
	primaries := []*net.TCPAddr{} // TCP addresses with IPv4 version
	fallback := []*net.TCPAddr{}  // TCP addresses with IPv6 version

	for _, ip := range ips {
		if ip.IP.To4() != nil {
			fallback = append(fallback, ip)
		} else {
			primaries = append(primaries, ip)
		}
	}

	// If there are no primaries, use fallbacks as primaries.
	if len(primaries) == 0 {
		if len(fallback) == 0 {
			return nil, errors.New("no addresses")
		}

		primaries = fallback
	}

	// Call DialParallel function with primaries and fallbacks.
	return DialParallel(ctx, primaries, fallback)
}

// https://github.com/golang/go/blob/315b6ae682a2a4e7718924a45b8b311a0fe10043/src/net/dial.go#L534
//
// dialParallel races two copies of dialSerial, giving the first a
// head start. It returns the first established connection and
// closes the others. Otherwise it returns an error from the first
// primary address.
func DialParallel(ctx context.Context, primaries []*net.TCPAddr, fallbacks []*net.TCPAddr) (net.Conn, error) {
	if len(fallbacks) == 0 {
		return DialSerial(ctx, primaries)
	}

	returned := make(chan struct{})
	defer close(returned)

	type dialResult struct {
		net.Conn
		error
		primary bool
		done    bool
	}
	results := make(chan dialResult) // unbuffered

	startRacer := func(ctx context.Context, primary bool) {
		ras := primaries
		if !primary {
			ras = fallbacks
		}
		c, err := DialSerial(ctx, ras)
		select {
		case results <- dialResult{Conn: c, error: err, primary: primary, done: true}:
		case <-returned:
			if c != nil {
				c.Close()
			}
		}
	}

	var primary, fallback dialResult

	// Start the main racer.
	primaryCtx, primaryCancel := context.WithCancel(ctx)
	defer primaryCancel()
	go startRacer(primaryCtx, true)

	// Start the timer for the fallback racer.
	//
	// rfc 8305 section 5
	//  This delay is referred
	//  to as the "Connection Attempt Delay".  One recommended value for a
	//  default delay is 250 milliseconds.
	fallbackTimer := time.NewTimer(time.Millisecond * 250)
	defer fallbackTimer.Stop()

	for {
		select {
		case <-fallbackTimer.C:
			fallbackCtx, fallbackCancel := context.WithCancel(ctx)
			defer fallbackCancel()
			go startRacer(fallbackCtx, false)

		case res := <-results:
			if res.error == nil {
				return res.Conn, nil
			}
			if res.primary {
				primary = res
			} else {
				fallback = res
			}
			if primary.done && fallback.done {
				return nil, primary.error
			}
			if res.primary && fallbackTimer.Stop() {
				// If we were able to stop the timer, that means it
				// was running (hadn't yet started the fallback), but
				// we just got an error on the primary path, so start
				// the fallback immediately (in 0 nanoseconds).
				fallbackTimer.Reset(0)
			}
		}
	}
}

// DialSerial connects to a list of addresses in sequence, returning
// either the first successful connection, or the first error.
func DialSerial(ctx context.Context, ras []*net.TCPAddr) (net.Conn, error) {
	var firstErr error // The error from the first address is most relevant.

	for i, ra := range ras {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		dialCtx, cancel, err := PartialDeadlineCtx(ctx, len(ras)-i)
		if err != nil {
			// Ran out of time.
			if firstErr == nil {
				firstErr = err
			}
			break
		}
		defer cancel()

		c, err := dialSingle(dialCtx, ra)
		if err == nil {
			return c, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}

	if firstErr == nil {
		firstErr = errors.New("errMissingAddress")
	}
	return nil, firstErr
}

func PartialDeadlineCtx(ctx context.Context, addrsRemaining int) (context.Context, context.CancelFunc, error) {
	dialCtx := ctx
	cancel := func() {}
	if deadline, hasDeadline := ctx.Deadline(); hasDeadline {
		partialDeadline, err := PartialDeadline(time.Now(), deadline, addrsRemaining)
		if err != nil {
			// Ran out of time.
			return dialCtx, cancel, err
		}
		if partialDeadline.Before(deadline) {
			dialCtx, cancel = context.WithDeadline(ctx, partialDeadline)
		}
	}

	return dialCtx, cancel, nil
}

func dialSingle(ctx context.Context, ips *net.TCPAddr) (net.Conn, error) {
	return DialContext(ctx, "tcp", ips.String())
}

// PartialDeadline returns the deadline to use for a single address,
// when multiple addresses are pending.
func PartialDeadline(now, deadline time.Time, addrsRemaining int) (time.Time, error) {
	if deadline.IsZero() {
		return deadline, nil
	}
	timeRemaining := deadline.Sub(now)
	if timeRemaining <= 0 {
		return time.Time{}, errors.New("errTimeout")
	}
	// Tentatively allocate equal time to each remaining address.
	timeout := timeRemaining / time.Duration(addrsRemaining)
	// If the time per address is too short, steal from the end of the list.
	const saneMinimum = 2 * time.Second
	if timeout < saneMinimum {
		timeout = min(timeRemaining, saneMinimum)
	}
	return now.Add(timeout), nil
}
