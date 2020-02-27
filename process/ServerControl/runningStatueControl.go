package ServerControl

import (
	"SsrMicroClient/MatchAndForward"
	config3 "SsrMicroClient/config"
	ssrinit "SsrMicroClient/init"
	httpserver "SsrMicroClient/net/proxy/http/server"
	socks5server "SsrMicroClient/net/proxy/socks5/server"
	"errors"
	"fmt"
	"log"
	"net/url"
)

type ServerControl struct {
	Socks5         *socks5server.ServerSocks5
	HttpS          *httpserver.HTTPServer
	forward        *MatchAndForward.ForwardTo
	setting        *config3.Setting
	Log            func(v ...interface{})
	ConfigJsonPath string
	RulePath       string
	wait           chan bool
}

func (ServerControl *ServerControl) serverControlInit() {
	var err error
	if ServerControl.setting, err = config3.SettingDecodeJSON(ssrinit.GetConfigAndSQLPath()); err != nil {
		log.Println(err)
	}
	ServerControl.RulePath = ServerControl.setting.BypassFile
	ServerControl.forward, err = MatchAndForward.NewForwardTo(ssrinit.GetConfigAndSQLPath(), ServerControl.RulePath)
	if err != nil {
		log.Println(err)
	}
	ServerControl.forward.Log = ServerControl.Log
	ServerControl.wait = make(chan bool, 0)
}

func (ServerControl *ServerControl) ServerStart() {
	ServerControl.serverControlInit()
	var err error
	socks5, err := url.Parse("//" + ServerControl.setting.Socks5WithBypassAddressAndPort)
	if err != nil {
		log.Println(err)
	}
	ServerControl.Socks5, err = socks5server.NewSocks5Server(socks5.Hostname(), socks5.Port(), "", "", ServerControl.forward.Forward)
	if err != nil {
		log.Println(err)
	}
	http, err := url.Parse("//" + ServerControl.setting.HttpProxyAddressAndPort)
	if err != nil {
		log.Println(err)
	}
	ServerControl.HttpS, err = httpserver.NewHTTPServer(http.Hostname(), http.Port(), "", "", ServerControl.forward.Forward)
	if err != nil {
		fmt.Println(err)
	}
	go func() {
		if err := ServerControl.Socks5.Socks5(); err != nil {
			log.Println(err)
			return
		}
	}()

	go func() {
		if err := ServerControl.HttpS.HTTPProxy(); err != nil {
			log.Println(err)
			return
		}
	}()
	go func() {
		ServerControl.wait <- true
	}()
}

func (ServerControl *ServerControl) ServerStop() (err error) {
	<-ServerControl.wait
	if ServerControl.Socks5 != nil {
		if err = ServerControl.Socks5.Close(); err != nil {
			log.Println(err)
		}
	}
	if ServerControl.HttpS != nil {
		if err = ServerControl.HttpS.Close(); err != nil {
			log.Println(err)
		}
	}
	if ServerControl.Socks5 != nil && ServerControl.HttpS != nil {
		ServerControl.HttpS.HTTPListener = nil
		ServerControl.HttpS = nil
		ServerControl.Socks5 = nil
		return nil
	}
	ServerControl.setting = nil
	ServerControl.RulePath = ""
	ServerControl.forward.Matcher.Release()
	ServerControl.forward.Matcher = nil
	ServerControl.forward.Setting = nil
	ServerControl.forward = nil
	close(ServerControl.wait)
	return errors.New("not Start")
}

func (ServerControl *ServerControl) ServerRestart() {
	if err := ServerControl.ServerStop(); err != nil {
		log.Println(err)
	} else {
		ServerControl.ServerStart()
	}
}
