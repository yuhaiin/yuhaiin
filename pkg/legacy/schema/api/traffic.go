package api

import (
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/legacy/schema/statistic"
)

type Counter struct {
	Download uint64 `json:"download"`
	Upload   uint64 `json:"upload"`
}

func (c *Counter) GetDownload() uint64 {
	if c == nil {
		return 0
	}
	return c.Download
}

func (c *Counter) GetUpload() uint64 {
	if c == nil {
		return 0
	}
	return c.Upload
}

type TotalFlow struct {
	Download uint64             `json:"download"`
	Upload   uint64             `json:"upload"`
	Counters map[uint64]Counter `json:"counters,omitempty"`
}

type TrafficTotals = TotalFlow

func (t *TotalFlow) GetDownload() uint64 {
	if t == nil {
		return 0
	}
	return t.Download
}

func (t *TotalFlow) GetUpload() uint64 {
	if t == nil {
		return 0
	}
	return t.Upload
}

func (t *TotalFlow) GetCounters() map[uint64]Counter {
	if t == nil {
		return nil
	}
	return t.Counters
}

type TrafficEvent struct {
	Type    string         `json:"type"`
	Payload jsontext.Value `json:"payload,omitempty"`
}

type NotifyNewConnections struct {
	Connections []*statistic.Connection `json:"connections"`
}

func (n *NotifyNewConnections) GetConnections() []*statistic.Connection {
	if n == nil {
		return nil
	}
	return n.Connections
}

type NotifyRemoveConnections struct {
	Ids []uint64 `json:"ids"`
}

func (n *NotifyRemoveConnections) GetIds() []uint64 {
	if n == nil {
		return nil
	}
	return n.Ids
}

type NotifyData struct {
	TotalFlow               *TotalFlow               `json:"totalFlow,omitempty"`
	NotifyNewConnections    *NotifyNewConnections    `json:"notifyNewConnections,omitempty"`
	NotifyRemoveConnections *NotifyRemoveConnections `json:"notifyRemoveConnections,omitempty"`
}

func (n *NotifyData) GetTotalFlow() *TotalFlow {
	if n == nil {
		return nil
	}
	return n.TotalFlow
}

func (n *NotifyData) GetNotifyNewConnections() *NotifyNewConnections {
	if n == nil {
		return nil
	}
	return n.NotifyNewConnections
}

func (n *NotifyData) GetNotifyRemoveConnections() *NotifyRemoveConnections {
	if n == nil {
		return nil
	}
	return n.NotifyRemoveConnections
}

func (n *NotifyNewConnections) MarshalJSON() ([]byte, error) {
	connections, err := marshalJSONRawSlice(n.GetConnections())
	if err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		Connections []jsontext.Value `json:"connections"`
	}{Connections: connections})
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
	Objects            []*FailedHistory `json:"objects"`
	DumpProcessEnabled bool             `json:"dump_process_enabled"`
}

func (l *FailedHistoryList) GetObjects() []*FailedHistory {
	if l == nil {
		return nil
	}
	return l.Objects
}

type AllHistory struct {
	Connection *statistic.Connection `json:"connection"`
	Count      uint64                `json:"count"`
	Time       time.Time             `json:"time"`
}

func (a *AllHistory) GetConnection() *statistic.Connection {
	if a == nil {
		return nil
	}
	return a.Connection
}

func (a *AllHistory) GetCount() uint64 {
	if a == nil {
		return 0
	}
	return a.Count
}

type AllHistoryList struct {
	Objects            []*AllHistory `json:"objects"`
	DumpProcessEnabled bool          `json:"dump_process_enabled"`
}

func (l *AllHistoryList) GetObjects() []*AllHistory {
	if l == nil {
		return nil
	}
	return l.Objects
}

func (a *AllHistory) MarshalJSON() ([]byte, error) {
	connection, err := marshalJSONRaw(a.Connection)
	if err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		Connection jsontext.Value `json:"connection"`
		Count      uint64         `json:"count"`
		Time       time.Time      `json:"time"`
	}{
		Connection: connection,
		Count:      a.Count,
		Time:       a.Time,
	})
}

func marshalJSONRaw(msg any) (jsontext.Value, error) {
	if msg == nil {
		return nil, nil
	}
	b, err := json.Marshal(msg)
	return jsontext.Value(b), err
}

func marshalJSONRawSlice[T any](items []T) ([]jsontext.Value, error) {
	out := make([]jsontext.Value, 0, len(items))
	for _, item := range items {
		b, err := marshalJSONRaw(item)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, nil
}
