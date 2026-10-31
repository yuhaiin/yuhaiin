package recovery

import "time"

// Import describes a bounded, expiring upload. It never contains the
// decryption input or exposes a filesystem path supplied by the client.
type Import struct {
	ID        string          `json:"id"`
	CreatedAt time.Time       `json:"createdAt"`
	ExpiresAt time.Time       `json:"expiresAt"`
	Size      int64           `json:"size"`
	SHA256    string          `json:"sha256"`
	State     string          `json:"state"`
	ErrorCode string          `json:"errorCode,omitempty"`
	PreviewID string          `json:"previewId,omitempty"`
	Preview   *RestorePreview `json:"preview,omitempty"`
}

// ImportActivateRequest binds destructive consent to one exact preview.
// It contains no private decryption input; activation uses authenticated staging.
type ImportActivateRequest struct {
	ID                         string `json:"id"`
	ConfirmPreviewID           string `json:"confirmPreviewId"`
	ConfirmBackupID            string `json:"confirmBackupId"`
	ConfirmSourceInstanceID    string `json:"confirmSourceInstanceId"`
	ConfirmTargetInstanceID    string `json:"confirmTargetInstanceId"`
	ConfirmResultInstanceID    string `json:"confirmResultInstanceId"`
	ConfirmMaintenance         bool   `json:"confirmMaintenance"`
	ConfirmStartupChanges      bool   `json:"confirmStartupChanges"`
	ConfirmSourceStopped       bool   `json:"confirmSourceStopped"`
	ConfirmCredentialRevival   bool   `json:"confirmCredentialRevival"`
	ConfirmIdentityReplacement bool   `json:"confirmIdentityReplacement"`
	ConfirmCloneEnrollment     bool   `json:"confirmCloneEnrollment"`
}

type ImportPreviewRequest struct {
	ID         string `json:"id"`
	Mode       string `json:"mode"`
	Identity   string `json:"identity,omitempty"`
	Passphrase string `json:"passphrase,omitempty"`
}
