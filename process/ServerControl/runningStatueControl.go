package ServerControl

import (
	"SsrMicroClient/config"
	"SsrMicroClient/init"
	"SsrMicroClient/net/proxy/http/server"
	"SsrMicroClient/net/proxy/socks5/server"
	"SsrMicroClient/process/MatchAndForward"
	"errors"
	"fmt"
	"log"
	"net/url"
)

type ServerControl struct {
	Socks5         *socks5server.ServerSocks5
	HttpS          *httpserver.HTTPServer
	forward        *MatchAndForward.ForwardFunc
	setting        *config.Setting
	Log            func(v ...interface{})
	ConfigJsonPath string
	RulePath       string
	wait           chan bool
	isInit         bool
}

func (s *ServerControl) init() {
	s.RulePath = s.setting.BypassFile
	var err error
	s.forward, err = MatchAndForward.NewForwardFunc(ssrinit.GetConfigAndSQLPath(), s.RulePath)
	if err != nil {
		log.Println(err)
	}
	s.forward.Log = s.Log
}

func (s *ServerControl) restartInit() {
	var err error
	if s.setting, err = config.SettingDecodeJSON(ssrinit.GetConfigAndSQLPath()); err != nil {
		log.Println(err)
	}
	s.wait = make(chan bool, 0)
	if !s.isInit {
		s.init()
		s.isInit = true
	}
}

func (s *ServerControl) ServerStart() {
	s.restartInit()
	var err error
	socks5, err := url.Parse("//" + s.setting.Socks5WithBypassAddressAndPort)
	if err != nil {
		log.Println(err)
	}
	s.Socks5, err = socks5server.NewSocks5Server(socks5.Hostname(), socks5.Port(), "", "", s.forward.Forward)
	if err != nil {
		log.Println(err)
	}
	http, err := url.Parse("//" + s.setting.HttpProxyAddressAndPort)
	if err != nil {
		log.Println(err)
	}
	s.HttpS, err = httpserver.NewHTTPServer(http.Hostname(), http.Port(), "", "", s.forward.Forward)
	if err != nil {
		fmt.Println(err)
	}
	go func() {
		if err := s.Socks5.Socks5(); err != nil {
			log.Println(err)
			return
		}
	}()

	go func() {
		if err := s.HttpS.HTTPProxy(); err != nil {
			log.Println(err)
			return
		}
	}()
	go func() {
		s.wait <- true
	}()
}

func (s *ServerControl) ServerStop() (err error) {
	<-s.wait
	if s.Socks5 != nil {
		if err = s.Socks5.Close(); err != nil {
			log.Println(err)
		}
	}
	if s.HttpS != nil {
		if err = s.HttpS.Close(); err != nil {
			log.Println(err)
		}
	}
	if s.Socks5 != nil && s.HttpS != nil {
		s.HttpS.HTTPListener = nil
		s.HttpS = nil
		s.Socks5 = nil
		return nil
	}
	s.setting = nil
	close(s.wait)
	return errors.New("not Start")
}

func (s *ServerControl) ServerRestart() {
	if err := s.ServerStop(); err != nil {
		log.Println(err)
	} else {
		s.ServerStart()
	}
}
