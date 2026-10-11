package native

import (
	"errors"
	"testing"
	"time"
)

func TestPushValidation(t *testing.T) {
	cfg := Config{Gateway: "127.0.0.1:1194", Username: "alice"}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	valid := "PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0,peer-id 16777215,cipher AES-128-GCM,ping 1,ping-restart 5"
	info, err := ParsePush(valid, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if info.Prefixes[0].String() != "10.8.0.2/24" || info.PingRestart != 5*time.Second {
		t.Fatalf("unexpected: %+v", info)
	}
	for _, reply := range []string{
		"PUSH_REPLY,ifconfig 10.8.0.2 255.0.255.0",
		"PUSH_REPLY,ifconfig 224.1.2.3 255.255.255.0",
		"PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0,peer-id 16777216",
		"PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0,cipher AES-256-CBC",
		"PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0,compress lz4",
		"PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0,ping -1",
		"PUSH_REPLY,ifconfig-ipv6 fd00::2/64 fd00::1,tun-mtu 1200",
		"PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0,tun-mtu 65536",
		"PUSH_REPLY",
	} {
		if _, err := ParsePush(reply, cfg); err == nil {
			t.Errorf("accepted invalid reply %q", reply)
		}
	}
	if _, err := ParsePush("AUTH_FAILED,bad password", cfg); !errors.Is(err, ErrAuth) {
		t.Fatal(err)
	}
}
func TestConfigurationRejectsUnsupportedModes(t *testing.T) {
	for _, cfg := range []Config{
		{Gateway: "127.0.0.1:1194", Username: "alice", Network: "sctp"},
		{Gateway: "127.0.0.1:1194", Username: "alice", DataCiphers: []string{"AES-256-CBC"}},
		{Gateway: "127.0.0.1:1194", ClientCertPEM: "without-key"},
		{Gateway: "127.0.0.1:1194", Username: "alice", TLSAuthKey: "key", TLSCryptKey: "key"},
		{Gateway: "127.0.0.1:1194", Username: "alice", MTU: 500},
		{Gateway: "127.0.0.1:1194", Username: "alice\x00bob"},
		{Gateway: "127.0.0.1:1194", Username: "alice", KeyDirection: 2},
	} {
		if err := cfg.Validate(); err == nil {
			t.Errorf("accepted invalid configuration")
		}
	}
}
