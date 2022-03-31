package main

// use cmd
//go:generate set VER=0,3,0,0
//go:generate set VER_STR=\\\"0.3.0.0\\\"
//go:generate windres.exe -D VER=%VER% -D VER_STR=%VER_STR% -o yuhaiin_windows_amd64.syso yuhaiin.rc
//go:generate windres.exe -D VER=%VER% -D VER_STR=%VER_STR% -F pe-i386 -o yuhaiin_windows_386.syso yuhaiin.rc -v

//powershell -Command 'windres.exe -D VER=%VER% -D VER_STR=%VER_STR% -o yuhaiin_windows_amd64.syso yuhaiin.rc'
//powershell -Command 'windres.exe -D VER=%VER% -D VER_STR=%VER_STR% -F pe-i386 -o yuhaiin_windows_386.syso yuhaiin.rc'

// version info rc file
// https://docs.microsoft.com/zh-cn/windows/win32/menurc/versioninfo-resource
