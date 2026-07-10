package backup

type Option struct {
	InstanceName   string `json:"instanceName"`
	S3             S3     `json:"s3"`
	Interval       uint64 `json:"interval"`
	LastBackupHash string `json:"lastBackupHash"`
}

type S3 struct {
	Enabled      bool   `json:"enabled"`
	AccessKey    string `json:"accessKey"`
	SecretKey    string `json:"secretKey"`
	Bucket       string `json:"bucket"`
	Region       string `json:"region"`
	EndpointURL  string `json:"endpointUrl"`
	UsePathStyle bool   `json:"usePathStyle"`
	StorageClass string `json:"storageClass"`
}

type RestoreOption struct {
	All        bool   `json:"all"`
	Rules      bool   `json:"rules"`
	Lists      bool   `json:"lists"`
	Nodes      bool   `json:"nodes"`
	Tags       bool   `json:"tags"`
	DNS        bool   `json:"dns"`
	Inbounds   bool   `json:"inbounds"`
	Subscribes bool   `json:"subscribes"`
	Source     string `json:"source"`
}
