package tools

// DiagnosticRequest selects a hostname, not a URL or a node configuration.
type DiagnosticRequest struct {
	Host string `json:"host"`
}

type DiagnosticCheck struct {
	ID         string   `json:"id"`
	Status     string   `json:"status"`  // pass, fail, warning, skipped
	Message    string   `json:"message"` // stable code for client translations
	DurationMS int64    `json:"durationMs"`
	Evidence   []string `json:"evidence"`
}

type DiagnosticReport struct {
	SchemaVersion int               `json:"schemaVersion"`
	StartedAt     string            `json:"startedAt"`
	DurationMS    int64             `json:"durationMs"`
	Host          string            `json:"host"`
	Platform      string            `json:"platform"`
	Version       string            `json:"version"`
	IPv6Enabled   bool              `json:"ipv6Enabled"`
	Checks        []DiagnosticCheck `json:"checks"`
	Findings      []string          `json:"findings"` // evidence-based guidance codes
	Report        string            `json:"report"`   // portable plain-text report, without credentials or raw logs
}
