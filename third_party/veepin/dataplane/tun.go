package dataplane

import "errors"

// ErrClosed is what a TUN read or write returns once Close has been called —
// including a read that was already parked waiting for a packet when it was.
//
// It exists so a data-path read loop can tell "the device went away because we
// shut it down" from a real device error worth logging. Pump.Run already makes
// that distinction with its own closing flag; a protocol running its own TUN
// loop should compare against this with errors.Is.
var ErrClosed = errors.New("dataplane: TUN is closed")
