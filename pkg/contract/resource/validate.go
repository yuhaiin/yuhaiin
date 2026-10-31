package resource

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
)

const (
	MaxShapingRate  = int64(1 << 40)
	MaxShapingBurst = int64(1 << 30)
)

var ErrInvalidRate = errors.New("trafficcontrol: invalid shaping rate or burst")

func ValidateRate(rate Rate) error {
	if rate.BytesPerSecond < 0 || rate.BytesPerSecond > MaxShapingRate || rate.BurstBytes < 0 || rate.BurstBytes > MaxShapingBurst || rate.BytesPerSecond == 0 && rate.BurstBytes != 0 {
		return ErrInvalidRate
	}
	return nil
}

func ValidateProfile(profile Profile) error {
	if err := ValidateRate(profile.Upload); err != nil {
		return fmt.Errorf("upload: %w", err)
	}
	if err := ValidateRate(profile.Download); err != nil {
		return fmt.Errorf("download: %w", err)
	}
	return nil
}

func ParseBytes(value string) (uint64, error) {
	if value == "" {
		return 0, nil
	}
	if len(value) > 19 {
		return 0, errors.New("byte limit exceeds SQLite's signed 64-bit range")
	}
	for _, c := range value {
		if c < '0' || c > '9' {
			return 0, errors.New("byte limits must be unsigned decimal strings")
		}
	}
	return strconv.ParseUint(value, 10, 63)
}

func ValidateLimits(limits Limits) error {
	for _, n := range []int64{limits.MaxTCPSessions, limits.MaxUDPSessions, limits.MaxSessions} {
		if n < 0 || n > 65536 {
			return errors.New("session limits must be between 0 and 65536")
		}
	}
	for _, n := range []float64{limits.ConnectionsPerSecond, limits.ConnectionBurst, limits.PacketsPerSecond, limits.PacketBurst} {
		if math.IsNaN(n) || math.IsInf(n, 0) || n < 0 || n > 1000000 {
			return errors.New("admission rates and bursts must be finite and between 0 and 1000000")
		}
	}
	if limits.ConnectionsPerSecond == 0 && limits.ConnectionBurst != 0 || limits.PacketsPerSecond == 0 && limits.PacketBurst != 0 || limits.ConnectionBurst > 0 && limits.ConnectionBurst < 1 || limits.PacketBurst > 0 && limits.PacketBurst < 1 {
		return errors.New("admission bursts require a rate and must allow at least one event")
	}
	return nil
}

func validID(id string) bool { return strings.TrimSpace(id) != "" && len(id) <= 128 }

func ValidateQuotas(quotas []Quota) error {
	if len(quotas) > 3 {
		return errors.New("configure at most one quota per UTC period")
	}
	periods := map[string]bool{}
	ids := map[string]bool{}
	for _, q := range quotas {
		if !validID(q.ID) || ids[q.ID] {
			return errors.New("quota IDs must be nonempty and unique")
		}
		ids[q.ID] = true
		if q.Period != "daily" && q.Period != "monthly" && q.Period != "lifetime" || periods[q.Period] {
			return errors.New("quota period must be daily, monthly or lifetime, without duplicates")
		}
		periods[q.Period] = true
		var total uint64
		for _, value := range []string{q.Upload, q.Download, q.Combined} {
			n, err := ParseBytes(value)
			if err != nil {
				return err
			}
			total |= n
		}
		if total == 0 {
			return errors.New("a quota requires at least one nonzero byte limit")
		}
		if q.Action != "block_new" && q.Action != "terminate" && q.Action != "throttle" && q.Action != "warn" {
			return errors.New("choose a quota enforcement action")
		}
		if err := ValidateProfile(q.ReducedSpeed); err != nil {
			return err
		}
		if q.Action == "throttle" && q.ReducedSpeed.Upload.BytesPerSecond == 0 && q.ReducedSpeed.Download.BytesPerSecond == 0 {
			return errors.New("throttling requires a reduced speed in at least one direction")
		}
		if len(q.Thresholds) > 10 {
			return errors.New("configure at most 10 quota thresholds")
		}
		seen := map[int]bool{}
		for _, threshold := range q.Thresholds {
			if threshold < 1 || threshold > 100 || seen[threshold] {
				return errors.New("quota thresholds must be unique percentages from 1 to 100")
			}
			seen[threshold] = true
		}
	}
	return nil
}

func ValidatePolicy(policy Policy) error {
	if err := ValidateProfile(policy.Profile); err != nil {
		return err
	}
	if err := ValidateLimits(policy.Limits); err != nil {
		return err
	}
	return ValidateQuotas(policy.Quotas)
}

func ValidateConfig(config Config) error {
	if config.Revision > 1<<53-1 {
		return errors.New("resource revision exceeds the exact JSON integer range")
	}
	if len(config.Groups) > 1024 || len(config.Users)+len(config.Credentials) > 8192 {
		return errors.New("resource policy has too many identity bindings")
	}
	if err := ValidatePolicy(config.DefaultUser); err != nil {
		return fmt.Errorf("default user: %w", err)
	}
	seen := map[string]bool{}
	for _, g := range config.Groups {
		if !validID(g.GroupID) || seen[g.GroupID] {
			return errors.New("invalid or duplicate group binding")
		}
		seen[g.GroupID] = true
		if err := ValidateProfile(g.SharedProfile); err != nil {
			return fmt.Errorf("group %s aggregate: %w", g.GroupID, err)
		}
		if err := ValidateProfile(g.IndividualProfile); err != nil {
			return fmt.Errorf("group %s individual: %w", g.GroupID, err)
		}
		if err := ValidateLimits(g.UserLimits); err != nil {
			return fmt.Errorf("group %s: %w", g.GroupID, err)
		}
		if err := ValidateQuotas(g.Quotas); err != nil {
			return fmt.Errorf("group %s: %w", g.GroupID, err)
		}
	}
	clear(seen)
	for _, u := range config.Users {
		if !validID(u.UserID) || seen[u.UserID] {
			return errors.New("invalid or duplicate user binding")
		}
		seen[u.UserID] = true
		if err := ValidatePolicy(u.Policy); err != nil {
			return fmt.Errorf("user %s: %w", u.UserID, err)
		}
	}
	clear(seen)
	for _, c := range config.Credentials {
		if !validID(c.CredentialID) || seen[c.CredentialID] {
			return errors.New("invalid or duplicate credential binding")
		}
		seen[c.CredentialID] = true
		if err := ValidatePolicy(c.Policy); err != nil {
			return fmt.Errorf("credential %s: %w", c.CredentialID, err)
		}
	}
	return nil
}
