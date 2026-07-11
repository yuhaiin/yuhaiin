package statistics

import (
	"context"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

func TestGetConnectionIncludesProcess(t *testing.T) {
	ctx := netapi.WithContext(context.Background())
	ctx.SetProcess("com.example.app", 123, 456)
	addr, err := netapi.ParseAddressPort("tcp", "example.com", 443)
	if err != nil {
		t.Fatal(err)
	}

	connection := new(Connections).getConnection(ctx, nil, addr, 1)
	if connection.Process != "com.example.app" {
		t.Fatalf("process = %q, want %q", connection.Process, "com.example.app")
	}
	if connection.PID != "123" {
		t.Fatalf("pid = %q, want %q", connection.PID, "123")
	}
	if connection.UID != "456" {
		t.Fatalf("uid = %q, want %q", connection.UID, "456")
	}
}
