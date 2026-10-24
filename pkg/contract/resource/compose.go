package resource

// IntersectLimits applies every nonzero cap. Burst defaults are resolved before
// composition, so a smaller group's implicit burst cannot be lifted by another
// group's explicit burst. The result does not depend on membership order.
func IntersectLimits(a, b Limits) Limits {
	return Limits{
		MaxTCPSessions:       capInt(a.MaxTCPSessions, b.MaxTCPSessions),
		MaxUDPSessions:       capInt(a.MaxUDPSessions, b.MaxUDPSessions),
		MaxSessions:          capInt(a.MaxSessions, b.MaxSessions),
		ConnectionsPerSecond: capFloat(a.ConnectionsPerSecond, b.ConnectionsPerSecond),
		ConnectionBurst:      capFloat(burst(a.ConnectionsPerSecond, a.ConnectionBurst), burst(b.ConnectionsPerSecond, b.ConnectionBurst)),
		PacketsPerSecond:     capFloat(a.PacketsPerSecond, b.PacketsPerSecond),
		PacketBurst:          capFloat(burst(a.PacketsPerSecond, a.PacketBurst), burst(b.PacketsPerSecond, b.PacketBurst)),
	}
}

// IntersectProfile composes individual per-user group caps into one user
// bucket. Shared aggregate group buckets remain separate and all apply.
func IntersectProfile(a, b Profile) Profile {
	return Profile{Upload: intersectRate(a.Upload, b.Upload), Download: intersectRate(a.Download, b.Download)}
}

func intersectRate(a, b Rate) Rate {
	if a.BytesPerSecond == 0 {
		return b
	}
	if b.BytesPerSecond == 0 {
		return a
	}
	if a.BurstBytes == 0 {
		a.BurstBytes = 64 << 10
	}
	if b.BurstBytes == 0 {
		b.BurstBytes = 64 << 10
	}
	return Rate{BytesPerSecond: min(a.BytesPerSecond, b.BytesPerSecond), BurstBytes: min(a.BurstBytes, b.BurstBytes)}
}
func capInt(a, b int64) int64 {
	if a == 0 {
		return b
	}
	if b == 0 {
		return a
	}
	return min(a, b)
}
func capFloat(a, b float64) float64 {
	if a == 0 {
		return b
	}
	if b == 0 {
		return a
	}
	return min(a, b)
}
func burst(rate, value float64) float64 {
	if rate == 0 {
		return 0
	}
	if value == 0 {
		return max(1, rate)
	}
	return value
}
