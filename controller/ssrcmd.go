package controller

import (
	"context"
	"fmt"
	"log"
	"net"
	"os/exec"
	"strconv"
	"strings"

	"github.com/Asutorufa/yuhaiin/subscr"
)

//"server":       "-s",
//"serverPort":   "-p",
//"method":       "-m",
//"password":     "-k",
//"localAddress": "-b",
//"localPort":    "-l",
//"obfs":         "-o",
//"obfsparam":    "-g",
//"protocol":     "-O",
//"protoparam":   "-G",
//
//"pidFile": "--pid-file",
////"logFile":            "--log-file",
////"connectVerboseInfo": "--connect-verbose-info",
//"workers":  "--workers",
//"fastOpen": "--fast-open",
//"acl":      "--acl",
//"timeout":  "-t",
//"udpTrans": "-u",

func GetFreePort() (string, error) {
	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	if err != nil {
		return "", err
	}
	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return "", err
	}
	defer func() {
		if err := l.Close(); err != nil {
			log.Println(err)
		}
	}()
	return strconv.Itoa(l.Addr().(*net.TCPAddr).Port), nil
}

func ShadowsocksrCmd(ctx context.Context, s *subscr.Shadowsocksr, ssrPath string) (ssrCmd *exec.Cmd, localHost string, err error) {
	LocalPort, err := GetFreePort()
	if err != nil {
		return nil, "", err
	}

	cmd := append([]string{}, strings.Split(ssrPath, " ")...)
	cmd = append(cmd, "-s", s.Server)
	cmd = append(cmd, "-p", s.Port)
	cmd = append(cmd, "-m", s.Method)
	cmd = append(cmd, "-k", s.Password)
	cmd = append(cmd, "-b", "127.0.0.1")
	cmd = append(cmd, "-l", LocalPort)
	if s.Obfs != "" {
		cmd = append(cmd, "-o", s.Obfs)
		cmd = append(cmd, "-g", s.Obfsparam)
	}
	if s.Protocol != "" {
		cmd = append(cmd, "-O", s.Protocol)
		cmd = append(cmd, "-G", s.Protoparam)
	}
	cmdE := exec.CommandContext(ctx, cmd[0], cmd[1:]...)
	//cmdE.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	fmt.Println(cmdE.String())
	return exec.CommandContext(ctx, cmd[0], cmd[1:]...), net.JoinHostPort("127.0.0.1", LocalPort), nil
}
