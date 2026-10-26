package backup

import "time"

// RecoveryImport describes a bounded, expiring upload. It never contains the
// decryption input or exposes a filesystem path supplied by the client.
type RecoveryImport struct {
	ID        string                  `json:"id"`
	CreatedAt time.Time               `json:"createdAt"`
	ExpiresAt time.Time               `json:"expiresAt"`
	Size      int64                   `json:"size"`
	SHA256    string                  `json:"sha256"`
	State     string                  `json:"state"`
	Preview   *RecoveryRestorePreview `json:"preview,omitempty"`
}

type RecoveryImportPreviewRequest struct {
	ID         string `json:"id"`
	Mode       string `json:"mode"`
	Identity   string `json:"identity,omitempty"`
	Passphrase string `json:"passphrase,omitempty"`
}
