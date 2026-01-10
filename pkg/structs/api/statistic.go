package api

import (
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/structs/statistic"
)

type Counter struct {
	Download uint64 `json:"download"`
	Upload   uint64 `json:"upload"`
}

type TotalFlow struct {
	Download uint64             `json:"download"`
	Upload   uint64             `json:"upload"`
	Counters map[uint64]Counter `json:"counters"`
}

type NotifyNewConnections struct {
	Connections []statistic.Connection `json:"connections"`
}

type NotifyRemoveConnections struct {
	Ids []uint64 `json:"ids"`
}

type NotifyDataChoiceType int32

const (
	NotifyDataChoiceTypeTotalFlow        NotifyDataChoiceType = 0
	NotifyDataChoiceTypeNewConnections   NotifyDataChoiceType = 1
	NotifyDataChoiceTypeRemoveConnections NotifyDataChoiceType = 2
)

type NotifyData struct {
	Type              NotifyDataChoiceType     `json:"type"`
	TotalFlow         *TotalFlow               `json:"total_flow,omitempty"`
	NewConnections    *NotifyNewConnections    `json:"notify_new_connections,omitempty"`
	RemoveConnections *NotifyRemoveConnections `json:"notify_remove_connections,omitempty"`
}

type FailedHistory struct {
	Protocol    statistic.Type `json:"protocol"`
	Host        string         `json:"host"`
	Error       string         `json:"error"`
	Process     string         `json:"process"`
	Time        time.Time      `json:"time"`
	FailedCount uint64         `json:"failed_count"`
}

type FailedHistoryList struct {
	Objects            []FailedHistory `json:"objects"`
	DumpProcessEnabled bool            `json:"dump_process_enabled"`
}

type AllHistory struct {
	Connection statistic.Connection `json:"connection"`
	Count      uint64               `json:"count"`
	Time       time.Time            `json:"time"`
}

type AllHistoryList struct {
	Objects            []AllHistory `json:"objects"`
	DumpProcessEnabled bool         `json:"dump_process_enabled"`
}

type Connections struct {
	Conns         Service[struct{}, NotifyNewConnections]
	CloseConn     Service[NotifyRemoveConnections, struct{}]
	Total         Service[struct{}, TotalFlow]
	Notify        Service[struct{}, <-chan NotifyData]
	FailedHistory Service[struct{}, FailedHistoryList]
	AllHistory    Service[struct{}, AllHistoryList]
}
