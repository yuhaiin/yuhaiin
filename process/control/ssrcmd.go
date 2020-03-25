package ServerControl

import (
	"github.com/Asutorufa/yuhaiin/config"
	"github.com/Asutorufa/yuhaiin/subscr"
	"log"
	"net"
	"os/exec"
	"strconv"
	"strings"
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

func ShadowsocksrCmd(s *subscr.Shadowsocksr) (*exec.Cmd, error) {
	configs, err := config.SettingDecodeJSON()
	if err != nil {
		return nil, err
	}
	configs.LocalAddress = "127.0.0.1"
	configs.LocalPort, err = GetFreePort()
	if err != nil {
		return nil, err
	}
	if err := config.SettingEnCodeJSON(configs); err != nil {
		return nil, err
	}
	cmd := append([]string{}, strings.Split(configs.SsrPath, " ")...)
	cmd = append(cmd, "-s", s.Server)
	cmd = append(cmd, "-p", s.Port)
	cmd = append(cmd, "-m", s.Method)
	cmd = append(cmd, "-k", s.Password)
	cmd = append(cmd, "-b", configs.LocalAddress)
	cmd = append(cmd, "-l", configs.LocalPort)
	if s.Obfs != "" {
		cmd = append(cmd, "-o", s.Obfs)
		cmd = append(cmd, "-g", s.Obfsparam)
	}
	if s.Protocol != "" {
		cmd = append(cmd, "-O", s.Protocol)
		cmd = append(cmd, "-G", s.Protoparam)
	}
	log.Println(cmd)
	return exec.Command(cmd[0], cmd[1:]...), nil
}
