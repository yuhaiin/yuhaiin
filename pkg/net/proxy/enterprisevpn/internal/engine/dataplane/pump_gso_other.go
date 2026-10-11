//go:build !linux

package dataplane

// runVnet never runs off Linux: only the Linux TUN can be opened in vnet mode,
// so NewPump never sets p.vnet elsewhere. The stub keeps Pump portable.
func (p *Pump) runVnet() {}
