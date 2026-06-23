package config

type S3 struct {
	Enabled       bool   `json:"enabled,omitempty"`
	AccessKey     string `json:"access_key,omitempty"`
	SecretKey     string `json:"secret_key,omitempty"`
	Bucket        string `json:"bucket,omitempty"`
	Region        string `json:"region,omitempty"`
	EndpointUrl   string `json:"endpoint_url,omitempty"`
	UsePathStyle  bool   `json:"use_path_style,omitempty"`
	StorageClass  string `json:"storage_class,omitempty"`
}

type BackupOption struct {
	InstanceName   string `json:"instance_name,omitempty"`
	S3             *S3    `json:"s3,omitempty"`
	Interval       uint64 `json:"interval,omitempty"`
	LastBackupHash string `json:"last_backup_hash,omitempty"`
}

type Setting struct {
	Ipv6                bool            `json:"ipv6,omitempty"`
	UseDefaultInterface bool            `json:"use_default_interface,omitempty"`
	NetInterface        string          `json:"net_interface,omitempty"`
	SystemProxy         *SystemProxy    `json:"system_proxy,omitempty"`
	Bypass              *BypassConfig   `json:"bypass,omitempty"`
	Dns                 *DnsConfig      `json:"dns,omitempty"`
	Server              *InboundConfig  `json:"server,omitempty"`
	Logcat              *Logcat         `json:"logcat,omitempty"`
	ConfigVersion       *ConfigVersion  `json:"config_version,omitempty"`
	Platform            *Platform       `json:"platform,omitempty"`
	AdvancedConfig      *AdvancedConfig `json:"advanced_config,omitempty"`
	Backup              *BackupOption   `json:"backup,omitempty"`
}

type AdvancedConfig struct {
	UdpBufferSize          int32 `json:"udp_buffer_size,omitempty"`
	RelayBufferSize        int32 `json:"relay_buffer_size,omitempty"`
	UdpRingbufferSize      int32 `json:"udp_ringbuffer_size,omitempty"`
	HappyeyeballsSemaphore int32 `json:"happyeyeballs_semaphore,omitempty"`
}

type SystemProxy struct {
	Http   bool `json:"http,omitempty"`
	Socks5 bool `json:"socks5,omitempty"`
}

type Info struct {
	Version   string   `json:"version,omitempty"`
	Commit    string   `json:"commit,omitempty"`
	BuildTime string   `json:"build_time,omitempty"`
	GoVersion string   `json:"go_version,omitempty"`
	Arch      string   `json:"arch,omitempty"`
	Platform  string   `json:"platform,omitempty"`
	Os        string   `json:"os,omitempty"`
	Compiler  string   `json:"compiler,omitempty"`
	Build     []string `json:"build,omitempty"`
}

type ConfigVersion struct {
	Version uint64 `json:"version,omitempty"`
}

type Platform struct {
	AndroidApp bool `json:"android_app,omitempty"`
}
