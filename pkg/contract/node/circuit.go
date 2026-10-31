package node

import "errors"

// CircuitConfig is optional on an automatic Selector. Manual selection and
// manual locks preserve legacy behavior. Failure/recovery/rate thresholds reuse
// SelectorPolicy; these fields govern admission and bounded recovery trials.
type CircuitConfig struct {
	Disabled            bool  `json:"disabled,omitzero"`
	CooldownMS          int64 `json:"cooldownMs,omitzero"`
	HalfOpenConcurrency int   `json:"halfOpenConcurrency,omitzero"`
	HalfOpenMaxRequests int   `json:"halfOpenMaxRequests,omitzero"`
	TrialTimeoutMS      int64 `json:"trialTimeoutMs,omitzero"`
}

func (c CircuitConfig) Effective(recovery int, cooldown int64) CircuitConfig {
	if c.CooldownMS == 0 {
		c.CooldownMS = cooldown
	}
	if c.HalfOpenConcurrency == 0 {
		c.HalfOpenConcurrency = 1
	}
	if c.HalfOpenMaxRequests == 0 {
		c.HalfOpenMaxRequests = max(4, recovery*2)
	}
	if c.TrialTimeoutMS == 0 {
		c.TrialTimeoutMS = 30000
	}
	return c
}
func (c CircuitConfig) Validate(recovery int) error {
	if c.Disabled {
		return nil
	}
	c = c.Effective(recovery, 30000)
	if c.CooldownMS < 1000 || c.CooldownMS > 86400000 || c.HalfOpenConcurrency < 1 || c.HalfOpenConcurrency > 16 || c.HalfOpenMaxRequests < recovery || c.HalfOpenMaxRequests > 256 || c.TrialTimeoutMS < 100 || c.TrialTimeoutMS > 120000 {
		return errors.New("circuit cooldown, trial concurrency, request quota or timeout out of range")
	}
	return nil
}

type CircuitStatus struct {
	State     string `json:"state"`
	OpenUntil int64  `json:"openUntil,omitzero"`
	InFlight  int    `json:"inFlight"`
	Issued    int    `json:"issued"`
	Recovered int    `json:"recovered"`
	Reason    string `json:"reason"`
}
