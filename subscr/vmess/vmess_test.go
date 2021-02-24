package vmess

import (
	"testing"
)

func TestGetVmess(t *testing.T) {
	data := "vmess://eyJob3N0IjoiIiwicGF0aCI6IiIsInRscyI6IiIsInZlc" +
		"mlmeV9jZXJ0Ijp0cnVlLCJhZGQiOiIxMjcuMC4wLjEiLCJwb3J" +
		"0IjowLCJhaWQiOjIsIm5ldCI6InRjcCIsInR5cGUiOiJub25lI" +
		"iwidiI6IjIiLCJwcyI6Im5hbWUiLCJpZCI6ImNjY2MtY2NjYy1" +
		"kZGRkLWFhYS00NmExYWFhYWFhIiwiY2xhc3MiOjF9Cg"
	t.Log(ParseLink([]byte(data), ""))
}
