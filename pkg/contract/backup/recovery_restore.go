package backup

type RecoveryRestorePreview struct {
	Manifest         RecoveryManifest `json:"manifest"`
	Mode             string           `json:"mode"`
	TargetInstanceID string           `json:"targetInstanceId"`
	InstanceID       string           `json:"instanceId"`
	Runtime          RecoveryRuntime  `json:"runtime"`
	Files            []RecoveryChange `json:"files"`
	Warnings         []string         `json:"warnings"`
}

type RecoveryChange struct {
	Path    string `json:"path"`
	Replace bool   `json:"replace"`
	Install bool   `json:"install"`
}

type RecoveryRestoreResult struct {
	BackupID      string          `json:"backupId"`
	TransactionID string          `json:"transactionId"`
	InstanceID    string          `json:"instanceId"`
	RecoveryPoint string          `json:"recoveryPoint"`
	State         string          `json:"state"`
	Runtime       RecoveryRuntime `json:"runtime"`
}
