package route

import "time"

type Config struct {
	DirectResolver       string `json:"directResolver"`
	ProxyResolver        string `json:"proxyResolver"`
	ResolveLocally       bool   `json:"resolveLocally"`
	UdpProxyFqdnStrategy string `json:"udpProxyFqdnStrategy"`
}

type ListConfig struct {
	RefreshInterval string         `json:"refreshInterval"`
	LastRefreshTime string         `json:"lastRefreshTime"`
	Error           string         `json:"error"`
	HostIndexDisk   bool           `json:"hostIndexDisk"`
	MaxMindDBGeoIP  MaxMindDBGeoIP `json:"maxMindDbGeoIp"`
}

type ListActivationStatus struct {
	HostIndexRefreshAt int64 `json:"hostIndexRefreshAt"`
}

type RuleActivationStatus struct {
	ApplyAt int64 `json:"applyAt"`
}

type ActivationStatus struct {
	HostIndexRefreshAt int64 `json:"hostIndexRefreshAt"`
	RuleApplyAt        int64 `json:"ruleApplyAt"`
}

type MaxMindDBGeoIP struct {
	DownloadURL string `json:"downloadUrl"`
	Error       string `json:"error"`
}

type RuleItem struct {
	Name      string `json:"name"`
	Disabled  bool   `json:"disabled"`
	Index     uint32 `json:"index"`
	Mode      string `json:"mode"`
	Tag       string `json:"tag"`
	Resolver  string `json:"resolver"`
	RuleCount uint32 `json:"ruleCount"`
}

type RouteRule struct {
	Name                 string     `json:"name"`
	Mode                 string     `json:"mode"`
	Tag                  string     `json:"tag,omitzero"`
	ResolveStrategy      string     `json:"resolveStrategy,omitzero"`
	UdpProxyFqdnStrategy string     `json:"udpProxyFqdnStrategy,omitzero"`
	Resolver             string     `json:"resolver,omitzero"`
	Rules                []RuleExpr `json:"rules,omitzero"`
	Disabled             bool       `json:"disabled,omitzero"`
}

type RuleExpr struct {
	Type    string       `json:"type"`
	All     []RuleExpr   `json:"all,omitzero"`
	Any     []RuleExpr   `json:"any,omitzero"`
	Not     *RuleExpr    `json:"not,omitzero"`
	Host    *ListRef     `json:"host,omitzero"`
	Process *ListRef     `json:"process,omitzero"`
	Inbound *SourceRef   `json:"inbound,omitzero"`
	Network *NetworkExpr `json:"network,omitzero"`
	Port    *PortExpr    `json:"port,omitzero"`
	GeoIP   *GeoIPExpr   `json:"geoip,omitzero"`
}

type ListRef struct {
	List string `json:"list"`
}

type SourceRef struct {
	Name  string   `json:"name,omitzero"`
	Names []string `json:"names,omitzero"`
}

type NetworkExpr struct {
	Network string `json:"network"`
}

type PortExpr struct {
	Ports string `json:"ports"`
}

type GeoIPExpr struct {
	Countries string `json:"countries"`
}

type RuleList struct {
	Items []RuleItem `json:"items"`
	Page  Page       `json:"page"`
}

type ListItem struct {
	Name       string `json:"name"`
	Type       string `json:"type"`
	Source     string `json:"source"`
	ItemCount  uint32 `json:"itemCount"`
	ErrorCount uint32 `json:"errorCount"`
	Preview    string `json:"preview"`
}

type RouteListDetail struct {
	Name      string     `json:"name"`
	Type      string     `json:"type"`
	Source    ListSource `json:"source"`
	ErrorMsgs []string   `json:"errorMsgs,omitzero"`
}

type ListSource struct {
	Type   string        `json:"type"`
	Local  *LocalSource  `json:"local,omitzero"`
	Remote *RemoteSource `json:"remote,omitzero"`
}

type LocalSource struct {
	Lists []string `json:"lists,omitzero"`
}

type RemoteSource struct {
	URLs []string `json:"urls,omitzero"`
}

type RouteList struct {
	Items []ListItem `json:"items"`
	Page  Page       `json:"page"`
}

type TagItem struct {
	Name string   `json:"name"`
	Type string   `json:"type"`
	Hash []string `json:"hash"`
}

type TagList struct {
	Items []TagItem `json:"items"`
	Page  Page      `json:"page"`
}

type SaveTagRequest struct {
	Tag  string `json:"tag"`
	Type string `json:"type"`
	Hash string `json:"hash"`
}

type Page struct {
	Page     int `json:"page"`
	PageSize int `json:"pageSize"`
	Total    int `json:"total"`
}

type RuleTestRequest struct {
	Host string `json:"host"`
}

type RuleTestResponse struct {
	Mode        string              `json:"mode"`
	Tag         string              `json:"tag"`
	Resolver    string              `json:"resolver"`
	AfterAddr   string              `json:"afterAddr"`
	Lists       []string            `json:"lists"`
	IPs         []string            `json:"ips"`
	MatchResult []MatchHistoryEntry `json:"matchResult"`
}

type MatchHistoryEntry struct {
	RuleName string        `json:"ruleName"`
	History  []MatchResult `json:"history"`
}

type MatchResult struct {
	ListName string `json:"listName"`
	Matched  bool   `json:"matched"`
}

type BlockHistory struct {
	Protocol   string    `json:"protocol"`
	Host       string    `json:"host"`
	Time       time.Time `json:"time"`
	Process    string    `json:"process"`
	BlockCount string    `json:"blockCount"`
}

type BlockHistoryList struct {
	Items              []BlockHistory `json:"items"`
	DumpProcessEnabled bool           `json:"dumpProcessEnabled"`
}

type Registry struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	URL       string `json:"url"`
	Enabled   bool   `json:"enabled"`
	Builtin   bool   `json:"builtin"`
	UpdatedAt string `json:"updatedAt"`
}

type RegistryList struct {
	Items []Registry `json:"items"`
}

type RegistryFile struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Category   string `json:"category"`
	Kind       string `json:"kind"`
	Usage      string `json:"usage"`
	ListType   string `json:"listType,omitzero"`
	Format     string `json:"format"`
	Path       string `json:"path"`
	URL        string `json:"url"`
	SourceURL  string `json:"sourceUrl,omitzero"`
	Size       int64  `json:"size"`
	SHA256     string `json:"sha256"`
	Selectable bool   `json:"selectable"`
}

type RegistryManifest struct {
	SchemaVersion int            `json:"schemaVersion"`
	Repository    string         `json:"repository"`
	Branch        string         `json:"branch"`
	BaseURL       string         `json:"baseUrl"`
	Files         []RegistryFile `json:"files"`
}

type RegistryCatalog struct {
	Registry      Registry       `json:"registry"`
	SchemaVersion int            `json:"schemaVersion"`
	Repository    string         `json:"repository"`
	Branch        string         `json:"branch"`
	BaseURL       string         `json:"baseUrl"`
	Files         []RegistryFile `json:"files"`
	Error         string         `json:"error,omitzero"`
}

type RegistryCatalogList struct {
	Items []RegistryCatalog `json:"items"`
}
