package trafficcontrol

import "time"

type rejection uint8

const (
	rejectNone rejection = iota
	rejectSessionLimit
	rejectConnectionRate
	rejectTCPLimit
	rejectUDPLimit
	rejectPacketRate
	rejectQuota
	rejectBandwidth
	rejectQuotaCredit
)

var rejectionNames = [...]string{"", "session_limit", "connection_rate", "tcp_limit", "udp_limit", "packet_rate", "quota_exhausted", "bandwidth_limit", "quota_credit_pending"}

func (g *IdentityGovernor) recordRejection(reason rejection, now time.Time) {
	g.lastRejected.Store(uint64(max(0, now.Unix()))<<8 | uint64(reason))
}

func (p Policy) recordRejection(reason rejection) {
	if p.manager == nil || p.identity == nil {
		return
	}
	r := p.manager.active.Load().resources
	if r == nil {
		return
	}
	if g := r.userGovernors[p.identity.UserID]; g != nil {
		g.recordRejection(reason, time.Now())
	}
}
