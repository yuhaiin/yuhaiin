package migrate

import (
	"strconv"

	contractconnection "github.com/Asutorufa/yuhaiin/pkg/contract/connection"
	schemaapi "github.com/Asutorufa/yuhaiin/pkg/legacy/schema/api"
	schemastatistic "github.com/Asutorufa/yuhaiin/pkg/legacy/schema/statistic"
)

func ConvertLegacyTotalFlow(in *schemaapi.TotalFlow) contractconnection.TotalFlow {
	if in == nil {
		return contractconnection.TotalFlow{Counters: map[string]contractconnection.Counter{}}
	}
	out := contractconnection.TotalFlow{
		Download: formatUint64(in.GetDownload()),
		Upload:   formatUint64(in.GetUpload()),
		Counters: make(map[string]contractconnection.Counter, len(in.GetCounters())),
	}
	for id, counter := range in.GetCounters() {
		out.Counters[formatUint64(id)] = contractconnection.Counter{
			Download: formatUint64(counter.Download),
			Upload:   formatUint64(counter.Upload),
		}
	}
	return out
}

func ConvertLegacyConnection(in *schemastatistic.Connection) contractconnection.Connection {
	var out contractconnection.Connection
	if in == nil {
		return out
	}
	out.ID = formatUint64(in.GetId())
	out.Addr = in.GetAddr()
	if netType := in.GetType(); netType != nil {
		out.Network = contractconnection.NetworkType{
			ConnType:       netType.GetConnType().String(),
			UnderlyingType: netType.GetUnderlyingType().String(),
		}
	}
	out.Source = in.GetSource()
	out.Inbound = in.GetInbound()
	out.InboundName = in.GetInboundName()
	out.Interface = in.GetInterface()
	out.Outbound = in.GetOutbound()
	out.LocalAddr = in.GetLocalAddr()
	out.Destination = in.GetDestionation()
	out.FakeIP = in.GetFakeIp()
	out.Hosts = in.GetHosts()
	out.Domain = in.GetDomain()
	out.IP = in.GetIp()
	out.Tag = in.GetTag()
	out.NodeID = in.GetHash()
	out.NodeName = in.GetNodeName()
	out.Protocol = in.GetProtocol()
	out.Process = in.GetProcess()
	out.PID = formatUint64(in.GetPid())
	out.UID = formatUint64(in.GetUid())
	out.TLSServerName = in.GetTlsServerName()
	out.HTTPHost = in.GetHttpHost()
	out.Component = in.GetComponent()
	out.UDPMigrateID = formatUint64(in.GetUdpMigrateId())
	if mode := in.GetMode(); mode != nil {
		out.Mode = mode.String()
	}
	out.MatchHistory = convertMatchHistory(in.GetMatchHistory())
	out.Resolver = in.GetResolver()
	out.Geo = in.GetGeo()
	out.OutboundGeo = in.GetOutboundGeo()
	out.Lists = in.GetLists()
	return out
}

func ConvertLegacyConnections(in *schemaapi.NotifyNewConnections) contractconnection.Connections {
	var out contractconnection.Connections
	if in == nil {
		return out
	}
	out.Connections = make([]contractconnection.Connection, 0, len(in.GetConnections()))
	for _, conn := range in.GetConnections() {
		out.Connections = append(out.Connections, ConvertLegacyConnection(conn))
	}
	return out
}

func ConvertLegacyFailedHistory(in *schemaapi.FailedHistoryList) contractconnection.FailedHistoryList {
	var out contractconnection.FailedHistoryList
	if in == nil {
		return out
	}
	out.DumpProcessEnabled = in.DumpProcessEnabled
	out.Items = make([]contractconnection.FailedHistory, 0, len(in.GetObjects()))
	for _, item := range in.GetObjects() {
		if item == nil {
			continue
		}
		out.Items = append(out.Items, contractconnection.FailedHistory{
			Protocol:    item.Protocol.String(),
			Host:        item.Host,
			Error:       item.Error,
			Process:     item.Process,
			Time:        item.Time,
			FailedCount: formatUint64(item.FailedCount),
		})
	}
	return out
}

func ConvertLegacyAllHistory(in *schemaapi.AllHistoryList) contractconnection.AllHistoryList {
	var out contractconnection.AllHistoryList
	if in == nil {
		return out
	}
	out.DumpProcessEnabled = in.DumpProcessEnabled
	out.Items = make([]contractconnection.AllHistory, 0, len(in.GetObjects()))
	for _, item := range in.GetObjects() {
		if item == nil {
			continue
		}
		out.Items = append(out.Items, contractconnection.AllHistory{
			Connection: ConvertLegacyConnection(item.GetConnection()),
			Count:      formatUint64(item.GetCount()),
			Time:       item.Time,
		})
	}
	return out
}

func ConvertLegacyNotifyData(in *schemaapi.NotifyData) contractconnection.Event {
	if in == nil {
		return contractconnection.Event{Type: "empty"}
	}
	if total := in.GetTotalFlow(); total != nil {
		return contractconnection.Event{Type: "total", Payload: ConvertLegacyTotalFlow(total)}
	}
	if added := in.GetNotifyNewConnections(); added != nil {
		return contractconnection.Event{Type: "connections_added", Payload: ConvertLegacyConnections(added)}
	}
	if removed := in.GetNotifyRemoveConnections(); removed != nil {
		ids := make([]string, 0, len(removed.GetIds()))
		for _, id := range removed.GetIds() {
			ids = append(ids, formatUint64(id))
		}
		return contractconnection.Event{Type: "connections_removed", Payload: contractconnection.CloseRequest{IDs: ids}}
	}
	return contractconnection.Event{Type: "empty"}
}

func convertMatchHistory(in []*schemastatistic.MatchHistoryEntry) []contractconnection.MatchHistoryEntry {
	out := make([]contractconnection.MatchHistoryEntry, 0, len(in))
	for _, entry := range in {
		if entry == nil {
			continue
		}
		history := make([]contractconnection.MatchResult, 0, len(entry.GetHistory()))
		for _, result := range entry.GetHistory() {
			if result == nil {
				continue
			}
			history = append(history, contractconnection.MatchResult{
				ListName: result.GetListName(),
				Matched:  result.GetMatched(),
			})
		}
		out = append(out, contractconnection.MatchHistoryEntry{
			RuleName: entry.GetRuleName(),
			History:  history,
		})
	}
	return out
}

func formatUint64(v uint64) string {
	if v == 0 {
		return "0"
	}
	return strconv.FormatUint(v, 10)
}
