package recovery

type RestoreStatus struct {
	PendingImportID  string         `json:"pendingImportId,omitempty"`
	PendingPreviewID string         `json:"pendingPreviewId,omitempty"`
	Result           *RestoreResult `json:"result,omitempty"`
}

type RestorePreview struct {
	Manifest         Manifest `json:"manifest"`
	Mode             string   `json:"mode"`
	TargetInstanceID string   `json:"targetInstanceId"`
	InstanceID       string   `json:"instanceId"`
	Runtime          Runtime  `json:"runtime"`
	Files            []Change `json:"files"`
	Warnings         []string `json:"warnings"`
}

type Change struct {
	Path    string `json:"path"`
	Replace bool   `json:"replace"`
	Install bool   `json:"install"`
}

type RestoreResult struct {
	BackupID      string  `json:"backupId"`
	TransactionID string  `json:"transactionId"`
	InstanceID    string  `json:"instanceId"`
	RecoveryPoint string  `json:"recoveryPoint"`
	State         string  `json:"state"`
	Runtime       Runtime `json:"runtime"`
	AdoptStartup  bool    `json:"adoptStartup,omitzero"`
}
