// Package transport defines shared, protocol-independent transport settings.
package transport

// TCPSettings configures the inner TCP stack used by VPN outbounds. Empty
// values preserve the profile defaults: BBR v3 and classic loss recovery.
// Settings apply when a stack is created; live connections are not migrated.
type TCPSettings struct {
	CongestionControl string `json:"congestionControl,omitempty"`
	LossRecovery      string `json:"lossRecovery,omitempty"`
}
