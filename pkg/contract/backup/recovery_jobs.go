package backup

import "time"

// RecoveryPolicy extends existing backup settings. It contains only a public
// encryption recipient; a scheduled encryptor never needs a private backup key.
type RecoveryPolicy struct {
	Enabled          bool   `json:"enabled"`
	Target           string `json:"target"`
	Recipient        string `json:"recipient"`
	IntervalMinutes  uint64 `json:"intervalMinutes"`
	TimeoutMinutes   uint64 `json:"timeoutMinutes"`
	KeepCount        int    `json:"keepCount"`
	KeepDays         int    `json:"keepDays"`
	IncludeHistory   bool   `json:"includeHistory"`
	AllowMaintenance bool   `json:"allowMaintenance"`
	ProtectUpdates   *bool  `json:"protectUpdates,omitempty"`
}

type RecoveryBackup struct {
	ID               string    `json:"id"`
	BackupID         string    `json:"backupId,omitempty"`
	InstanceID       string    `json:"instanceId,omitempty"`
	CreatedAt        time.Time `json:"createdAt"`
	CompletedAt      time.Time `json:"completedAt,omitzero"`
	Target           string    `json:"target"`
	State            string    `json:"state"`
	Size             int64     `json:"size"`
	SHA256           string    `json:"sha256,omitempty"`
	ObjectKey        string    `json:"objectKey,omitempty"`
	Verification     string    `json:"verification,omitempty"`
	ErrorCode        string    `json:"errorCode,omitempty"`
	IncludesHistory  bool      `json:"includesHistory"`
	UploadAttempts   int       `json:"uploadAttempts"`
	ArchiveCheck     string    `json:"archiveCheck,omitempty"`
	ArchiveCheckedAt time.Time `json:"archiveCheckedAt,omitzero"`
	// LocalState is observed by the runtime, never trusted as a durable file lease.
	LocalState         string    `json:"localState,omitempty"`
	Retrieval          string    `json:"retrieval,omitempty"`
	RetrievalErrorCode string    `json:"retrievalErrorCode,omitempty"`
	RetrievedAt        time.Time `json:"retrievedAt,omitzero"`
	UpdatePoint        bool      `json:"updatePoint,omitzero"`
}

type RecoveryRetrieveRequest struct {
	ID              string `json:"id"`
	ConfirmDownload bool   `json:"confirmDownload"`
	ConfirmReplace  bool   `json:"confirmReplace"`
}

// Decryption material is transient request input. It is never stored in backup
// settings/history or returned by a configuration or verification endpoint.
type RecoveryVerifyRequest struct {
	ID         string `json:"id"`
	Identity   string `json:"identity,omitempty"`
	Passphrase string `json:"passphrase,omitempty"`
}

type RecoveryBackupRequest struct {
	ConfirmMaintenance bool `json:"confirmMaintenance"`
}

type RecoveryBackupStatus struct {
	Supported bool             `json:"supported"`
	Reason    string           `json:"reason,omitempty"`
	Items     []RecoveryBackup `json:"items"`
}
