package auth

import (
    "testing"
    "time"
)

func TestPasskeyRPOrigins(t *testing.T) {
    tests := []struct {
        origin string
        want string
    }{
        {"https://vpn.example.com", "vpn.example.com"},
        {"https://ui.example.com:8443", "ui.example.com"},
        {"http://localhost:50051", "localhost"},
        {"https://localhost:50051", "localhost"},
        {"http://vpn.example.com", ""},
        {"http://127.0.0.1:50051", ""},
        {"https://192.168.1.2", ""},
        {"https://[::1]:50051", ""},
        {"https://vpn.example.com/path", ""},
        {"https://vpn.example.com?redirect=https://evil.example", ""},
        {"https://user@vpn.example.com", ""},
        {"null", ""},
    }
    for _, tt := range tests {
        t.Run(tt.origin, func(t *testing.T) {
            got, err := passkeyRP(tt.origin)
            if tt.want == "" && err == nil {
                t.Fatalf("accepted invalid origin %q as %q", tt.origin, got)
            }
            if tt.want != "" && (err != nil || got != tt.want) {
                t.Fatalf("passkeyRP(%q) = %q, %v; want %q", tt.origin, got, err, tt.want)
            }
        })
    }
}

func TestPasskeyFlowsAreBoundAndSingleUse(t *testing.T) {
    p := &PasskeyService{flows: make(map[string]passkeyFlow)}
    original := passkeyFlow{origin:"http://localhost:50051", rpID:"localhost",owner:"alice",sessionID:"session"}
    token, err := p.put(original)
    if err != nil { t.Fatal(err) }
    if _, err := p.take(token, "https://vpn.example.com", "vpn.example.com"); err == nil {
        t.Fatal("cross-origin finish accepted")
    }
    if _, err := p.take(token, original.origin, original.rpID); err == nil {
        t.Fatal("failed cross-origin attempt did not consume challenge")
    }
    token, err = p.put(original)
    if err != nil { t.Fatal(err) }
    if _, err := p.take(token, original.origin, original.rpID); err != nil { t.Fatal(err) }
    if _, err := p.take(token, original.origin, original.rpID); err == nil { t.Fatal("replay accepted") }

    token, err = p.put(original)
    if err != nil { t.Fatal(err) }
    p.mu.Lock()
    flow := p.flows[token]
    flow.expires = time.Now().Add(-time.Second)
    p.flows[token] = flow
    p.mu.Unlock()
    if _, err := p.take(token, original.origin, original.rpID); err == nil { t.Fatal("expired flow accepted") }
}
