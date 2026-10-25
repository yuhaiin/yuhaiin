package node

import "errors"

// SpeedTestRequest is an explicit administrator action. No automatic tests are
// enabled by creating a selector. Zero limits select conservative defaults.
type SpeedTestRequest struct {
	URL              string `json:"url"`
	MaxBytes         int64  `json:"maxBytes,omitzero"`
	DurationMS       int64  `json:"durationMs,omitzero"`
	TimeoutMS        int64  `json:"timeoutMs,omitzero"`
	DailyBudgetBytes int64  `json:"dailyBudgetBytes,omitzero"`
}

func (r SpeedTestRequest) Effective() SpeedTestRequest {
	if r.MaxBytes == 0 {
		r.MaxBytes = 4 << 20
	}
	if r.DurationMS == 0 {
		r.DurationMS = 5000
	}
	if r.TimeoutMS == 0 {
		r.TimeoutMS = 10000
	}
	if r.DailyBudgetBytes == 0 {
		r.DailyBudgetBytes = 64 << 20
	}
	return r
}
func (r SpeedTestRequest) Validate() error {
	r = r.Effective()
	if err := validateHTTPSProbeURL(r.URL); err != nil {
		return err
	}
	if r.MaxBytes < 1024 || r.MaxBytes > 64<<20 || r.DurationMS < 100 || r.DurationMS > 15000 || r.TimeoutMS < r.DurationMS || r.TimeoutMS > 30000 || r.DailyBudgetBytes < r.MaxBytes || r.DailyBudgetBytes > 1<<30 {
		return errors.New("speed test exceeds byte, duration, timeout, or daily budget limits")
	}
	return nil
}
