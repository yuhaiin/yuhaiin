package statistics

import (
	"path/filepath"
	"testing"

	contractconnection "github.com/Asutorufa/yuhaiin/pkg/contract/connection"
)

func TestMatchTraceLazyLifecycleAndSnapshotIsolation(t *testing.T) {
	c := NewSQLiteConnStore(filepath.Join(t.TempDir(), "state.db"), nil)
	defer c.Close()

	oldTemplate := &contractconnection.MatchTraceTemplate{
		Type: "and",
		Children: []contractconnection.MatchTraceTemplate{
			{Type: "condition", Label: "host", EmitsHistory: true},
			{Type: "condition", Label: "port", EmitsHistory: true},
		},
	}
	oldInfo := performanceInfo(42)
	oldInfo.MatchHistory = []contractconnection.MatchHistoryEntry{{
		RuleID:        "policy",
		RuleName:      "policy",
		History:       []contractconnection.MatchResult{{ListName: "host", Matched: true}, {ListName: "port", Matched: true}},
		TraceTemplate: oldTemplate,
	}}
	c.storeConnection(performanceConnection(42), oldInfo)

	assertHit := func(where string) {
		t.Helper()
		resp, ok := c.MatchTraceForConnection(42, 0)
		if !ok || resp.Entry.Trace == nil || resp.Entry.Trace.State != "hit" ||
			resp.Entry.Trace.Type != "and" || len(resp.Entry.Trace.Children) != 2 {
			t.Fatalf("%s: unexpected old connection trace: %+v (ok=%v)", where, resp, ok)
		}
	}
	assertHit("pending")
	if err := c.persistence.flush(); err != nil {
		t.Fatal(err)
	}
	// The SQLite copy deliberately lacks the runtime-only shared template.
	fromStore, ok := c.infoStore.Load(42)
	if !ok || fromStore.MatchHistory[0].TraceTemplate != nil || fromStore.MatchHistory[0].Trace != nil {
		t.Fatalf("expanded trace leaked into SQLite: %+v", fromStore.MatchHistory)
	}
	assertHit("persisted")

	// Simulate a new routing generation. Earlier connections must retain the
	// template in use when they were routed, not reinterpret with new policy.
	newTemplate := &contractconnection.MatchTraceTemplate{Type: "condition", Constant: "false"}
	newInfo := performanceInfo(43)
	newInfo.MatchHistory = []contractconnection.MatchHistoryEntry{{
		RuleID: "policy", RuleName: "policy", TraceTemplate: newTemplate,
	}}
	c.storeConnection(performanceConnection(43), newInfo)
	assertHit("after policy update")
	newResp, ok := c.MatchTraceForConnection(43, 0)
	if !ok || newResp.Entry.Trace == nil || newResp.Entry.Trace.State != "miss" {
		t.Fatalf("new connection did not use new template: %+v, ok=%v", newResp, ok)
	}

	ptrs, ok := c.traceStore.Load(42)
	if !ok || len(ptrs) != 1 || ptrs[0] != oldTemplate {
		t.Fatal("live trace index did not retain one shared template pointer")
	}
	c.Remove(42)
	if _, ok := c.traceStore.Load(42); ok {
		t.Fatal("closed connection retained its trace template")
	}
	if _, ok := c.MatchTraceForConnection(42, 0); ok {
		t.Fatal("closed connection trace was still readable")
	}
	c.Remove(43)
}

func TestMatchTraceOnlyExpandsRequestedRule(t *testing.T) {
	c := NewSQLiteConnStore(filepath.Join(t.TempDir(), "state.db"), nil)
	defer c.Close()
	info := performanceInfo(10)
	info.MatchHistory = []contractconnection.MatchHistoryEntry{
		{RuleName: "first", TraceTemplate: &contractconnection.MatchTraceTemplate{Type: "condition", Constant: "false"}},
		{RuleName: "second", TraceTemplate: &contractconnection.MatchTraceTemplate{Type: "condition", Constant: "true"}},
	}
	c.storeConnection(performanceConnection(10), info)
	response, ok := c.MatchTraceForConnection(10, 1)
	if !ok || response.RuleIndex != 1 || response.Entry.RuleName != "second" ||
		response.Entry.Trace == nil || response.Entry.Trace.State != "hit" {
		t.Fatalf("unexpected selected rule trace: %+v (ok=%v)", response, ok)
	}
	for _, index := range []int{-1, 2} {
		if _, ok := c.MatchTraceForConnection(10, index); ok {
			t.Fatalf("out-of-range rule index %d accepted", index)
		}
	}
	c.Remove(10)
}
