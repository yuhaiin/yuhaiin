package route

import "time"

type Config struct {
	Revision             uint64 `json:"revision"`
	DefaultMode          string `json:"defaultMode"`
	DefaultTarget        Target `json:"defaultTarget"`
	DirectResolver       string `json:"directResolver"`
	ProxyResolver        string `json:"proxyResolver"`
	ResolveLocally       bool   `json:"resolveLocally"`
	UdpProxyFqdnStrategy string `json:"udpProxyFqdnStrategy"`
}

type ListConfig struct {
	Revision        uint64         `json:"revision"`
	RefreshInterval string         `json:"refreshInterval"`
	LastRefreshTime string         `json:"lastRefreshTime"`
	Error           string         `json:"error"`
	HostIndexDisk   bool           `json:"hostIndexDisk"`
	MaxMindDBGeoIP  MaxMindDBGeoIP `json:"maxMindDbGeoIp"`
}

type ListActivationStatus struct {
	HostIndexRefreshAt int64 `json:"hostIndexRefreshAt"`
}

// ListActivationIssue describes a remote resource that could not be loaded
// during the currently applied routing snapshot.
type ListActivationIssue struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Error       string `json:"error"`
	Unavailable bool   `json:"unavailable"`
}

// SkippedRouteRule is never evaluated when a referenced list is unavailable.
// In particular, NOT over a missing list must not match every destination.
type SkippedRouteRule struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	ListIDs []string `json:"listIds"`
}

type RuleActivationStatus struct {
	ListIssues      []ListActivationIssue `json:"listIssues,omitzero"`
	SkippedRules    []SkippedRouteRule   `json:"skippedRules,omitzero"`
	Applying        bool    `json:"applying,omitzero"`
	RunningConfig   *Config `json:"runningConfig,omitzero"`
	SavedRevision   uint64  `json:"savedRevision"`
	AppliedRevision uint64  `json:"appliedRevision"`
	ApplyAt         int64   `json:"applyAt"`
	Error           string  `json:"error,omitempty"`
}

type ActivationStatus struct {
	ListIssues         []ListActivationIssue `json:"listIssues,omitzero"`
	SkippedRules       []SkippedRouteRule   `json:"skippedRules,omitzero"`
	Applying           bool    `json:"applying,omitzero"`
	RunningConfig      *Config `json:"runningConfig,omitzero"`
	SavedRevision      uint64  `json:"savedRevision"`
	AppliedRevision    uint64  `json:"appliedRevision"`
	HostIndexRefreshAt int64   `json:"hostIndexRefreshAt"`
	RuleApplyAt        int64   `json:"ruleApplyAt"`
	Error              string  `json:"error,omitempty"`
}

type MaxMindDBGeoIP struct {
	DownloadURL string `json:"downloadUrl"`
	Error       string `json:"error"`
}

type RuleItem struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Disabled  bool   `json:"disabled"`
	Index     uint32 `json:"index"`
	Mode      string `json:"mode"`
	Target    Target `json:"target"`
	Resolver  string `json:"resolver"`
	RuleCount uint32 `json:"ruleCount"`
}

type RouteRule struct {
	ID                   string     `json:"id"`
	Revision             uint64     `json:"revision"`
	Name                 string     `json:"name"`
	Mode                 string     `json:"mode"`
	Target               Target     `json:"target"`
	ResolveStrategy      string     `json:"resolveStrategy,omitzero"`
	UdpProxyFqdnStrategy string     `json:"udpProxyFqdnStrategy,omitzero"`
	Resolver             string     `json:"resolver,omitzero"`
	Rules                []RuleExpr `json:"rules,omitzero"`
	Disabled             bool       `json:"disabled,omitzero"`
}

// Target distinguishes a specific node, a shared selector, and the current
// global selection without requiring an alias for ordinary routing rules.
// Type gateway is reserved for a TCP routing rule with Mode gateway; it is not
// an outbound node and cannot be a Gateway HTTP action or the global default.
type Target struct {
	Type string `json:"type"`
	ID   string `json:"id,omitzero"`
}

// RuleDraft is an editable view of one rule and its exclusively owned lists.
// Shared lists remain references in Rule; matching data never lives in Rule.
type RuleDraft struct {
	// ShareLists promotes the named owned lists during this save transaction.
	ShareLists []string          `json:"shareLists,omitempty"`
	Rule       RouteRule         `json:"rule"`
	Lists      []RouteListDetail `json:"lists"`
}

type Reference struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
	Name string `json:"name"`
}

type RuleExpr struct {
	Type    string        `json:"type"`
	Always  *MatchAllExpr `json:"always,omitzero"`
	All     []RuleExpr    `json:"all,omitzero"`
	Any     []RuleExpr    `json:"any,omitzero"`
	Not     *RuleExpr     `json:"not,omitzero"`
	Host    *ListRef      `json:"host,omitzero"`
	Process *ListRef      `json:"process,omitzero"`
	Inbound *SourceRef    `json:"inbound,omitzero"`
	Network *NetworkExpr  `json:"network,omitzero"`
	Port    *PortExpr     `json:"port,omitzero"`
	GeoIP   *GeoIPExpr    `json:"geoip,omitzero"`
}

type MatchAllExpr struct{}

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
	ID          string `json:"id"`
	OwnerRuleID string `json:"ownerRuleId,omitzero"`
	Name        string `json:"name"`
	Type        string `json:"type"`
	Source      string `json:"source"`
	ItemCount   uint32 `json:"itemCount"`
	ErrorCount  uint32 `json:"errorCount"`
	Preview     string `json:"preview"`
}

type RouteListDetail struct {
	Revision    uint64     `json:"revision"`
	ID          string     `json:"id"`
	OwnerRuleID string     `json:"ownerRuleId,omitzero"`
	Name        string     `json:"name"`
	Type        string     `json:"type"`
	Source      ListSource `json:"source"`
	ErrorMsgs   []string   `json:"errorMsgs,omitzero"`
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

type Page struct {
	Page     int `json:"page"`
	PageSize int `json:"pageSize"`
	Total    int `json:"total"`
}

type RuleTestRequest struct {
	Host string `json:"host"`
}

type RuleTestResponse struct {
	Target      Target              `json:"target"`
	Mode        string              `json:"mode"`
	Resolver    string              `json:"resolver"`
	AfterAddr   string              `json:"afterAddr"`
	ListNames   map[string]string   `json:"listNames,omitempty"`
	Lists       []string            `json:"lists"`
	IPs         []string            `json:"ips"`
	MatchResult []MatchHistoryEntry `json:"matchResult"`
}

type MatchHistoryEntry struct {
	RuleID   string        `json:"ruleId,omitempty"`
	RuleName string        `json:"ruleName"`
	History  []MatchResult `json:"history"`
}

type MatchResult struct {
	Kind     string `json:"kind,omitempty"`
	ID       string `json:"id,omitempty"`
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

// GeoIPCountries describes the country values of the currently applied database.
type GeoIPCountries struct {
	Codes  []string `json:"codes"`
	Loaded bool     `json:"loaded"`
}
