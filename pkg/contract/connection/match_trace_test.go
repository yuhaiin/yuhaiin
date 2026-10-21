package connection

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
)

func TestReconstructMatchTraceShortCircuit(t *testing.T) {
	template := &MatchTraceTemplate{Type: "and", Children: []MatchTraceTemplate{
		{Type: "or", Children: []MatchTraceTemplate{
			{Type: "condition", EmitsHistory: true},
			{Type: "condition", EmitsHistory: true},
			{Type: "condition", EmitsHistory: true},
		}},
		{Type: "not", Children: []MatchTraceTemplate{{Type: "condition", EmitsHistory: true}}},
		{Type: "condition", EmitsHistory: true},
	}}
	history := []MatchResult{
		{ListName: "first", Matched: false},
		{ListName: "second", Matched: true},
		{ListName: "excluded", Matched: false},
		{ListName: "after", Matched: false},
	}
	out := ReconstructMatchTrace(template, history)
	if out.State != "miss" || out.Children[0].State != "hit" || out.Children[0].Children[2].State != "skipped" ||
		out.Children[1].State != "hit" || out.Children[2].State != "miss" {
		t.Fatalf("unexpected %+v", out)
	}
}
func TestReconstructMatchTraceUnknown(t *testing.T) {
	template := &MatchTraceTemplate{Type: "not", Children: []MatchTraceTemplate{{Type: "condition", EmitsHistory: true}}}
	out := ReconstructMatchTrace(template, []MatchResult{{Kind: "list-unavailable", Matched: false}})
	if out.State != "unknown" || out.Children[0].State != "unknown" {
		t.Fatalf("NOT unknown must remain unknown: %+v", out)
	}
}
func TestReconstructMatchTraceMissingHistoryDoesNotInventResult(t *testing.T) {
	template := &MatchTraceTemplate{Type: "condition", EmitsHistory: true}
	if out := ReconstructMatchTrace(template, nil); out.State != "unknown" {
		t.Fatalf("missing history must not be treated as miss: %+v", out)
	}
}

func TestSharedMatchTemplateNotSerialized(t *testing.T) {
	shared := &MatchTraceTemplate{
		Type:     "or",
		Children: []MatchTraceTemplate{{Type: "condition", Label: "example", EmitsHistory: true}},
	}
	entry := MatchHistoryEntry{RuleName: "example", TraceTemplate: shared, History: []MatchResult{{Matched: true}}}
	data, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "traceTemplate") || strings.Contains(string(data), "\"trace\"") {
		t.Fatalf("shared topology leaked into default connection JSON: %s", data)
	}
	reconstructed := ReconstructMatchTrace(entry.TraceTemplate, entry.History)
	if reconstructed.State != "hit" {
		t.Fatalf("unexpected replay: %+v", reconstructed)
	}
	if shared.Children[0].Label != "example" {
		t.Fatal("reconstruction mutated the shared template")
	}
}


// BenchmarkMatchTraceOnDemand deliberately measures the expensive operation
// in the detail RPC, not the per-connection routing/storage hot path.
func BenchmarkMatchTraceOnDemand(b *testing.B) {
	for _, size := range []int{16, 128, 1024} {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			leaves := make([]MatchTraceTemplate, size)
			history := make([]MatchResult, size)
			for i := range leaves {
				leaves[i] = MatchTraceTemplate{Type: "condition", Label: "list", EmitsHistory: true}
				history[i] = MatchResult{ListName: "list", Matched: false}
			}
			template := &MatchTraceTemplate{Type: "or", Label: "test", Children: leaves}
			b.ReportAllocs()
			for b.Loop() {
				out := ReconstructMatchTrace(template, history)
				if out == nil || out.State != "miss" {
					b.Fatal("unexpected trace")
				}
			}
		})
	}
}
