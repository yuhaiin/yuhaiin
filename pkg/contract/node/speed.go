package node

// SpeedTestRequest is an explicit administrator action. No automatic tests are
// enabled by creating a selector. Zero limits select conservative defaults.
type SpeedTestRequest struct {
	URL              string `json:"url"`
	MaxBytes         int64  `json:"maxBytes,omitzero"`
	DurationMS       int64  `json:"durationMs,omitzero"`
	TimeoutMS        int64  `json:"timeoutMs,omitzero"`
	DailyBudgetBytes int64  `json:"dailyBudgetBytes,omitzero"`
}
