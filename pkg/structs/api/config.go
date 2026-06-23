package api

import (
	"net/http"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/structs/config"
	"github.com/Asutorufa/yuhaiin/pkg/structs/statistic"
)

type Service[R, P any] struct{}

type ConfigService struct {
	Load Service[struct{}, config.Setting]
	Save Service[config.Setting, struct{}]
	Info Service[struct{}, config.Info]
}

type Client[R, P any] struct {
	hc *http.Client
}

func NewClient[R, P any](impl Service[R, P]) Client[R, P] {
	return Client[R, P]{
		hc: &http.Client{},
	}
}

type TestResponse struct {
	Mode        config.ModeConfig             `json:"mode"`
	AfterAddr   string                        `json:"after_addr"`
	MatchResult []statistic.MatchHistoryEntry `json:"match_result"`
	Lists       []string                      `json:"lists"`
	Ips         []string                      `json:"ips"`
}

type BlockHistory struct {
	Protocol   string    `json:"protocol"`
	Host       string    `json:"host"`
	Time       time.Time `json:"time"`
	Process    string    `json:"process"`
	BlockCount uint64    `json:"block_count"`
}

type BlockHistoryList struct {
	Objects            []BlockHistory `json:"objects"`
	DumpProcessEnabled bool           `json:"dump_process_enabled"`
}

type ListResponse struct {
	Names          []string              `json:"names"`
	MaxminddbGeoip config.MaxminddbGeoip `json:"maxminddb_geoip"`
	RefreshConfig  config.RefreshConfig  `json:"refresh_config"`
}

type SaveListConfigRequest struct {
	MaxminddbGeoip  config.MaxminddbGeoip `json:"maxminddb_geoip"`
	RefreshInterval uint64                `json:"refresh_interval"`
}

type Lists struct {
	List       Service[struct{}, ListResponse]
	Get        Service[string, config.List]
	Save       Service[config.List, struct{}]
	Remove     Service[string, struct{}]
	Refresh    Service[struct{}, struct{}]
	SaveConfig Service[SaveListConfigRequest, struct{}]
}

type RuleResponse struct {
	Names []string `json:"names"`
}

type RuleIndex struct {
	Index uint32 `json:"index"`
	Name  string `json:"name"`
}

type RuleSaveRequest struct {
	Index RuleIndex     `json:"index"`
	Rule  config.Rulev2 `json:"rule"`
}

type ChangePriorityOperate int32

const (
	ChangePriorityOperateExchange     ChangePriorityOperate = 0
	ChangePriorityOperateInsertBefore ChangePriorityOperate = 1
	ChangePriorityOperateInsertAfter  ChangePriorityOperate = 2
)

type ChangePriorityRequest struct {
	Source  RuleIndex             `json:"source"`
	Target  RuleIndex             `json:"target"`
	Operate ChangePriorityOperate `json:"operate"`
}

type Rules struct {
	List           Service[struct{}, RuleResponse]
	Get            Service[RuleIndex, config.Rulev2]
	Save           Service[RuleSaveRequest, struct{}]
	Remove         Service[RuleIndex, struct{}]
	ChangePriority Service[ChangePriorityRequest, struct{}]
	Config         Service[struct{}, config.Configv2]
	SaveConfig     Service[config.Configv2, struct{}]
	Test           Service[string, TestResponse]
	BlockHistory   Service[struct{}, BlockHistoryList]
}

type InboundsResponse struct {
	Names           []string     `json:"names"`
	HijackDns       bool         `json:"hijack_dns"`
	HijackDnsFakeip bool         `json:"hijack_dns_fakeip"`
	Sniff           config.Sniff `json:"sniff"`
}

type PlatformDarwin struct {
	NetworkServices []string `json:"network_services"`
}

type PlatformInfoResponse struct {
	Darwin PlatformDarwin `json:"darwin"`
}

type Inbound struct {
	List         Service[struct{}, InboundsResponse]
	Get          Service[string, config.Inbound]
	Save         Service[config.Inbound, config.Inbound]
	Remove       Service[string, struct{}]
	Apply        Service[InboundsResponse, struct{}]
	PlatformInfo Service[struct{}, PlatformInfoResponse]
}

type ResolveList struct {
	Names []string `json:"names"`
}

type SaveResolver struct {
	Name     string     `json:"name"`
	Resolver config.Dns `json:"resolver"`
}

type Hosts struct {
	Hosts map[string]string `json:"hosts"`
}

type Resolver struct {
	List        Service[struct{}, ResolveList]
	Get         Service[string, config.Dns]
	Save        Service[SaveResolver, config.Dns]
	Remove      Service[string, struct{}]
	Hosts       Service[struct{}, Hosts]
	SaveHosts   Service[Hosts, struct{}]
	Fakedns     Service[struct{}, config.FakeDnsConfig]
	SaveFakedns Service[config.FakeDnsConfig, struct{}]
	Server      Service[struct{}, string]
	SaveServer  Service[string, struct{}]
}
