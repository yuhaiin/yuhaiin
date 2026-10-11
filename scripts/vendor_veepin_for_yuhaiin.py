#!/usr/bin/env python3
"""Pin the MIT-licensed veepin engine for userspace outbound adapters.

This script is intentionally one-shot: never sync an arbitrary moving HEAD into a
security-critical VPN without reviewing the diff. Keep upstream attribution.
"""
from __future__ import annotations
import pathlib
import shutil
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
VERSION = "810e017596c0b5b55bc0da563929bde13a6b201d"
TARGET = ROOT / "third_party" / "veepin"
if TARGET.exists():
    raise SystemExit("third_party/veepin already exists; review upgrades manually")

with tempfile.TemporaryDirectory(prefix="veepin-vendor-") as tmp:
    source = pathlib.Path(tmp) / "veepin"
    subprocess.run(["git", "clone", "--quiet", "--filter=blob:none", "https://github.com/xen0bit/veepin", str(source)], check=True)
    subprocess.run(["git", "-C", str(source), "checkout", "--detach", VERSION], check=True)
    TARGET.mkdir(parents=True)
    # Copy only packages used by the four client implementations. No OS hooks,
    # CLI executables, test fixtures or private deployment scripts are installed.
    for d in ("client", "dataplane", "anyconnect", "sstp", "fortinet", "ikev2", "internal"):
        for file in (source / d).rglob("*"):
            if not file.is_file() or file.name.endswith("_test.go"):
                continue
            if file.suffix != ".go":
                continue
            to = TARGET / file.relative_to(source)
            to.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(file, to)
    for f in ("LICENSE", "go.mod", "go.sum"):
        shutil.copy2(source / f, TARGET / f)

(TARGET / "UPSTREAM.md").write_text(
    "# Vendored veepin protocol engines\\n\\n"
    f"Source: https://github.com/xen0bit/veepin at \`{VERSION}\`\\n\\n"
    "Licensed MIT; see LICENSE. Go package layout and public API are preserved.\\n"
    "Only protocol packages needed by yuhaiin were copied.\\n"
    "The changes in this copy add a virtual TUN injection point and per-session\\n"
    "transport dialers. Do not replace with upstream blindly.\\n"
)

def edit(name, before, after):
    f = TARGET / name
    s = f.read_text()
    if before not in s:
        raise ValueError(f"{name}: expected source not found: {before[:100]!r}")
    f.write_text(s.replace(before, after, 1))

virtual = """package dataplane

import (
    "errors"
    "sync"
)

// VirtualPacketIO represents a packet-oriented, non-host TUN.
type VirtualPacketIO interface {
    Read([]byte) (int, error)
    Write([]byte) (int, error)
    Close() error
}

var virtualDevices sync.Map // name -> VirtualPacketIO, consumed once

func RegisterVirtualTUN(name string, io VirtualPacketIO) (func(), error) {
    if name == "" || io == nil { return nil, errors.New("virtual TUN requires a unique name and device") }
    if _, loaded := virtualDevices.LoadOrStore(name, io); loaded {
        return nil, errors.New("virtual TUN already registered")
    }
    return func() { virtualDevices.Delete(name) }, nil
}
func consumeVirtualTUN(name string) (VirtualPacketIO, bool) {
    v, ok := virtualDevices.LoadAndDelete(name)
    if !ok { return nil, false }
    return v.(VirtualPacketIO), true
}
"""
(TARGET / "dataplane" / "virtual_tun.go").write_text(virtual)
for platform in ("linux", "darwin", "other"):
    filename = f"dataplane/tun_{platform}.go"
    if platform == "other":
        edit(filename, "type TUN struct{}", "type TUN struct{ name string; virtual VirtualPacketIO }")
    else:
        edit(filename, "type TUN struct {", "type TUN struct {\n\tvirtual VirtualPacketIO")
    if platform == "other":
        edit(filename, "func OpenTUN(name string) (*TUN, error) {", 'func OpenTUN(name string) (*TUN, error) {\n\tif v,ok:=consumeVirtualTUN(name);ok{return &TUN{name:name,virtual:v},nil}')
    else:
        edit(filename, "func OpenTUN(name string) (*TUN, error) {", 'func OpenTUN(name string) (*TUN, error) {\n\tif v,ok:=consumeVirtualTUN(name);ok{return &TUN{name:name,virtual:v},nil}')
    if platform == "linux":
        edit(filename,"func OpenTUNGSO(name string) (*TUN, error) {",
             'func OpenTUNGSO(name string) (*TUN, error) {\n\tif v,ok:=consumeVirtualTUN(name);ok{return &TUN{name:name,virtual:v},nil}')
    if platform == "other":
        edit(filename, 'func (t *TUN) Name() string { return "" }','func (t *TUN) Name() string { return t.name }')
        edit(filename, 'func (t *TUN) Read(buf []byte) (int, error) {',
             'func (t *TUN) Read(buf []byte) (int, error) {\n\tif t.virtual!=nil{return t.virtual.Read(buf)}')
        edit(filename, 'func (t *TUN) Write(pkt []byte) (int, error) {',
             'func (t *TUN) Write(pkt []byte) (int, error) {\n\tif t.virtual!=nil{return t.virtual.Write(pkt)}')
        edit(filename, "func (t *TUN) Close() error { return nil }",
             'func (t *TUN) Close() error { if t.virtual!=nil{return t.virtual.Close()};return nil }')
    else:
        edit(filename, "func (t *TUN) Name() string {",
             'func (t *TUN) Name() string {\n\tif t!=nil && t.virtual!=nil{return t.name}\n')
        if platform=="linux":
            # Linux does not use the same GSO declaration as macOS.
            edit(filename,'func (t *TUN) GSO() bool { return t != nil && t.vnet }',
                 'func (t *TUN) GSO() bool { return t != nil && t.virtual==nil && t.vnet }')
        edit(filename, "func (t *TUN) Read(buf []byte) (int, error) {",
             'func (t *TUN) Read(buf []byte) (int, error) {\n\tif t.virtual!=nil{return t.virtual.Read(buf)}')
        edit(filename, "func (t *TUN) Write(pkt []byte) (int, error) {",
             'func (t *TUN) Write(pkt []byte) (int, error) {\n\tif t.virtual!=nil{return t.virtual.Write(pkt)}')
        edit(filename, "func (t *TUN) Close() error {",
             'func (t *TUN) Close() error {\n\tif t.virtual!=nil{return t.virtual.Close()}')

# Inject DialContext explicitly in each client configuration. When non-nil it
# MUST be used for every TCP connection. The yuhaiin wrapper sets NoDTLS on
# chained transports so UDP cannot fall back to a direct socket.
dial_field = '\n\tDialContext func(context.Context,string,string)(net.Conn,error)'
edit("anyconnect/anyconnect.go", "type Config struct {", "type Config struct {"+dial_field)
edit("anyconnect/anyconnect.go",
     'conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsCfg)',
     '''var conn *tls.Conn
    var err error
    if cfg.DialContext != nil {
        var raw net.Conn
        raw,err=cfg.DialContext(ctx,"tcp",addr)
        if err==nil {
            conn=tls.Client(raw,tlsCfg)
            err=conn.HandshakeContext(ctx)
            if err!=nil{conn.Close()}
        }
    } else { conn,err=tls.DialWithDialer(dialer,"tcp",addr,tlsCfg) }''')
edit("sstp/sstp.go","type Config struct {","type Config struct {"+dial_field)
edit("sstp/sstp.go",'tlsConn, err := dialTLS(ctx, addr, tlsCfg)',
     'tlsConn, err := dialTLS(ctx, addr, tlsCfg, cfg.DialContext)')
edit("sstp/sstp.go",'func dialTLS(ctx context.Context, addr string, tlsCfg *tls.Config) (*tls.Conn, error) {',
     '''func dialTLS(ctx context.Context, addr string, tlsCfg *tls.Config, dial func(context.Context,string,string)(net.Conn,error)) (*tls.Conn, error) {
    if dial!=nil{
        raw,err:=dial(ctx,"tcp",addr);if err!=nil{return nil,err}
        conn:=tls.Client(raw,tlsCfg)
        if err:=conn.HandshakeContext(ctx);err!=nil{conn.Close();return nil,err}
        return conn,nil
    }''')
edit("fortinet/fortinet.go","type Config struct {","type Config struct {"+dial_field)
edit("fortinet/fortinet.go",
     'hc := &http.Client{Jar: jar, Transport: &http.Transport{TLSClientConfig: tlsConfig}}',
     'hc := &http.Client{Jar: jar, Transport: &http.Transport{TLSClientConfig: tlsConfig, DialContext: cfg.DialContext, Proxy: nil}}')
edit("fortinet/fortinet.go",
     'c, err := dialDataPath(host, cookie, fcfg, tlsConfig, tun, logger, !cfg.NoDTLS)',
     'c, err := dialDataPath(host, cookie, fcfg, tlsConfig, tun, logger, !cfg.NoDTLS, cfg.DialContext)')
edit("fortinet/fortinet.go",
     'tun io.ReadWriteCloser, logger *vlog.Logger, wantDTLS bool,',
     'tun io.ReadWriteCloser, logger *vlog.Logger, wantDTLS bool, dial func(context.Context,string,string)(net.Conn,error),')
edit("fortinet/fortinet.go",
     'c, err := dialTLSPath(host, cookie, fcfg, tlsConfig, tun, logger)',
     'c, err := dialTLSPath(host, cookie, fcfg, tlsConfig, tun, logger, dial)')
edit("fortinet/fortinet.go",
     'tun io.ReadWriteCloser, logger *vlog.Logger,\n) (*ifortinet.Client, error) {',
     'tun io.ReadWriteCloser, logger *vlog.Logger, dial func(context.Context,string,string)(net.Conn,error),\n) (*ifortinet.Client, error) {')
edit("fortinet/fortinet.go",
     'conn, err := tls.Dial("tcp", host, tlsConfig)',
     '''var conn *tls.Conn
    var err error
    if dial!=nil {
        raw,e:=dial(context.Background(),"tcp",host)
        if e!=nil{return nil,e}
        conn=tls.Client(raw,tlsConfig)
        err=conn.Handshake()
        if err!=nil{conn.Close()}
    } else {conn,err=tls.Dial("tcp",host,tlsConfig)}''')
# IKEv2 TCP mode uses a single stream for both control and ESP. Fail closed
# at the yuhaiin boundary if a chain cannot carry UDP NAT-T.
edit("ikev2/client.go","type Config struct {","type Config struct {"+dial_field)
edit("ikev2/client.go",'TCP:             cfg.TCP,','TCP:             cfg.TCP,\n\t\tDialContext: cfg.DialContext,')
edit("internal/ikev2/ike/client.go", "import (", 'import (\n\t"context"')
edit("internal/ikev2/ike/client.go",
     'type ClientConfig struct {',
     'type ClientConfig struct {\n\tDialContext func(context.Context,string,string)(net.Conn,error)')
edit("internal/ikev2/ike/client.go",
     'dialTCPStream(c.cfg.ServerHost, c.cfg.NATTPort, tcpDialTimeout)',
     'dialTCPStream(c.cfg.ServerHost, c.cfg.NATTPort, tcpDialTimeout, c.cfg.DialContext)')
edit("internal/ikev2/ike/tcpstream.go",
     'func dialTCPStream(host string, port int, timeout time.Duration) (*TCPStream, error) {',
     'func dialTCPStream(host string, port int, timeout time.Duration, dial func(context.Context,string,string)(net.Conn,error)) (*TCPStream, error) {')
edit("internal/ikev2/ike/tcpstream.go",
     'c, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), timeout)',
     '''var c net.Conn
    var err error
    if dial!=nil {
        ctx,cancel:=context.WithTimeout(context.Background(),timeout)
        defer cancel()
        c,err=dial(ctx,"tcp",net.JoinHostPort(host,strconv.Itoa(port)))
    }else{c,err=net.DialTimeout("tcp",net.JoinHostPort(host,strconv.Itoa(port)),timeout)}''')
edit("internal/ikev2/ike/tcpstream.go", 'import (', 'import (\n\t"context"')

subprocess.run(["gofmt", "-w", *[str(p) for p in TARGET.rglob("*.go")]],check=True)
print(f"Vendored MIT veepin {VERSION} with virtual TUN and upstream TCP injection")
