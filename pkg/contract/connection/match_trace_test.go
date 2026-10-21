package connection

import "testing"

func TestReconstructMatchTraceShortCircuit(t *testing.T) {
	template := &MatchTraceTemplate{Type:"and", Children: []MatchTraceTemplate{
		{Type:"or",Children:[]MatchTraceTemplate{
			{Type:"condition",EmitsHistory:true},
			{Type:"condition",EmitsHistory:true},
			{Type:"condition",EmitsHistory:true},
		}},
		{Type:"not",Children:[]MatchTraceTemplate{{Type:"condition",EmitsHistory:true}}},
		{Type:"condition",EmitsHistory:true},
	}}
	history := []MatchResult{
		{ListName:"first",Matched:false},
		{ListName:"second",Matched:true},
		{ListName:"excluded",Matched:false},
		{ListName:"after",Matched:false},
	}
	out:=ReconstructMatchTrace(template,history)
	if out.State!="miss"||out.Children[0].State!="hit"||out.Children[0].Children[2].State!="skipped"||
		out.Children[1].State!="hit"||out.Children[2].State!="miss" {
		t.Fatalf("unexpected %+v",out)
	}
}
func TestReconstructMatchTraceUnknown(t *testing.T) {
	template := &MatchTraceTemplate{Type:"not",Children:[]MatchTraceTemplate{{Type:"condition",EmitsHistory:true}}}
	out:=ReconstructMatchTrace(template,[]MatchResult{{Kind:"list-unavailable",Matched:false}})
	if out.State!="unknown" || out.Children[0].State!="unknown" {
		t.Fatalf("NOT unknown must remain unknown: %+v",out)
	}
}
func TestReconstructMatchTraceMissingHistoryDoesNotInventResult(t *testing.T) {
	template := &MatchTraceTemplate{Type:"condition",EmitsHistory:true}
	if out:=ReconstructMatchTrace(template,nil);out.State!="unknown" {
		t.Fatalf("missing history must not be treated as miss: %+v",out)
	}
}
