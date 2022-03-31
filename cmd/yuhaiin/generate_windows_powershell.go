package main

// use powershell
//go:generate $env:VER="0,3,0,0"
//go:generate $env:VER_STR='\\\"0.3.0.0\\\"'
//go:generate windres.exe -D VER=$env:VER -D VER_STR=$env:VER_STR -o yuhaiin_windows_amd64.syso yuhaiin.rc
// go:generate windres.exe -D VER=$env:VER -D VER_STR=$env:VER_STR -F pe-i386 -o yuhaiin_windows_386.syso yuhaiin.rc -v

// version info rc file
// https://docs.microsoft.com/zh-cn/windows/win32/menurc/versioninfo-resource
