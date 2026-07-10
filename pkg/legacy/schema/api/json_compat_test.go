package api

import (
	json "encoding/json/v2"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/legacy/schema/statistic"
)

func TestChangePriorityOperateUnmarshalLegacyString(t *testing.T) {
	var got ChangePriorityRequest
	if err := json.Unmarshal([]byte(`{"operate":"InsertBefore"}`), &got); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if got.Operate != ChangePriorityRequest_InsertBefore {
		t.Fatalf("Operate = %v, want %v", got.Operate, ChangePriorityRequest_InsertBefore)
	}
}

func TestTrafficUnmarshalLegacyStringUint64(t *testing.T) {
	var total TotalFlow
	if err := json.Unmarshal([]byte(`{
		"download":"100",
		"upload":"200",
		"counters":{"42":{"download":"3","upload":"4"}}
	}`), &total); err != nil {
		t.Fatalf("unmarshal total failed: %v", err)
	}
	if total.Download != 100 || total.Upload != 200 {
		t.Fatalf("flow = download %d upload %d", total.Download, total.Upload)
	}
	if total.Counters[42].Download != 3 || total.Counters[42].Upload != 4 {
		t.Fatalf("counter = %#v", total.Counters[42])
	}

	var remove NotifyRemoveConnections
	if err := json.Unmarshal([]byte(`{"ids":["1",2]}`), &remove); err != nil {
		t.Fatalf("unmarshal remove failed: %v", err)
	}
	if len(remove.Ids) != 2 || remove.Ids[0] != 1 || remove.Ids[1] != 2 {
		t.Fatalf("Ids = %#v", remove.Ids)
	}
}

func TestHistoryUnmarshalLegacyStringUint64(t *testing.T) {
	var block BlockHistory
	if err := json.Unmarshal([]byte(`{"block_count":"9"}`), &block); err != nil {
		t.Fatalf("unmarshal block failed: %v", err)
	}
	if block.BlockCount != 9 {
		t.Fatalf("BlockCount = %d, want 9", block.BlockCount)
	}

	var failed FailedHistory
	if err := json.Unmarshal([]byte(`{"protocol":"tcp","failed_count":"8"}`), &failed); err != nil {
		t.Fatalf("unmarshal failed history failed: %v", err)
	}
	if failed.Protocol != statistic.Type_tcp || failed.FailedCount != 8 {
		t.Fatalf("failed history = protocol %v count %d", failed.Protocol, failed.FailedCount)
	}

	var all AllHistory
	if err := json.Unmarshal([]byte(`{"count":"7","connection":{"id":"6","type":{"connType":"tcp"}}}`), &all); err != nil {
		t.Fatalf("unmarshal all history failed: %v", err)
	}
	if all.Count != 7 || all.Connection == nil || all.Connection.Id != 6 || all.Connection.GetType().GetConnType() != statistic.Type_tcp {
		t.Fatalf("all history = count %d connection %#v", all.Count, all.Connection)
	}
}
