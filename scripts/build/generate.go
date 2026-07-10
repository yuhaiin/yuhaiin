package scripts

import _ "golang.org/x/mobile/bind"

// windows exe icon and describe
// windres from minGW64 https://sourceforge.net/projects/mingw-w64/files/mingw-w64/mingw-w64-release/
// qt set application icon https://github.com/therecipe/qt/wiki/Setting-the-Application-Icon
//go:generate windres.exe -o yuhaiin_windows_amd64.syso yuhaiin.rc
//go:generate windres.exe -F pe-i386 -o yuhaiin_windows_386.syso yuhaiin.rc

// hide windows cmd window while runnig kernel
//go:generate go build -ldflags="-H windowsgui -w -s" -tags api -o deploy/yuhaiin_kernel.exe

// windows debug gui
//go:generate set QT_DEBUG_CONSOLE=true
//go:generate qtdeploy build

// generate platform assets
