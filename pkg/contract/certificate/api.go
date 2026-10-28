package certificate

import "time"

type SaveRequest struct {
	Certificate Config `json:"certificate"`
	Revision    uint64 `json:"revision"`
}
type RevisionRequest struct {
	ID       string `json:"id"`
	Revision uint64 `json:"revision"`
}

// ProviderWrite is accepted only by the management mutation endpoint. Token is
// write-only and must never be returned through a provider/config projection.
type ProviderWrite struct {
	Provider DNSProvider `json:"provider"`
	Token    string      `json:"token,omitempty"`
}
type Event struct {
	Sequence uint64    `json:"sequence"`
	At       time.Time `json:"at"`
	Code     string    `json:"code"`
}
type Overview struct {
	Certificates []Resource    `json:"certificates"`
	Providers    []DNSProvider `json:"providers"`
	Events       []Event       `json:"events"`
}
