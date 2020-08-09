package gui

import (
	"context"
	"runtime"

	"github.com/Asutorufa/yuhaiin/config"
	"github.com/Asutorufa/yuhaiin/gui/sysproxy"
	"github.com/golang/protobuf/ptypes/empty"

	"github.com/therecipe/qt/core"
	"github.com/therecipe/qt/gui"
	"github.com/therecipe/qt/widgets"
)

type setting struct {
	window *widgets.QMainWindow

	// Proxy
	systemProxy        *widgets.QCheckBox // gui only
	redirHostLabel     *widgets.QLabel
	httpHostLabel      *widgets.QLabel
	socks5HostLabel    *widgets.QLabel
	redirHostLineText  *widgets.QLineEdit
	httpHostLineText   *widgets.QLineEdit
	socks5HostLineText *widgets.QLineEdit

	// DNS
	dohCheckBox       *widgets.QCheckBox
	dnsProxyCheckBox  *widgets.QCheckBox
	dnsServerLabel    *widgets.QLabel
	dnsServerLineText *widgets.QLineEdit
	dnsSubNetLabel    *widgets.QLabel
	dnsSubNetLineText *widgets.QLineEdit

	// BYPASS
	bypassCheckBox *widgets.QCheckBox
	bypassLineText *widgets.QLineEdit

	// DIRECT DNS
	directDnsDOH       *widgets.QCheckBox
	directDnsHostLabel *widgets.QLabel
	directDnsHost      *widgets.QLineEdit

	// BUTTON
	applyButton    *widgets.QPushButton
	reImportButton *widgets.QPushButton
}

func NewSetting() *setting {
	s := &setting{}
	s.window = widgets.NewQMainWindow(nil, core.Qt__Window)
	s.window.SetWindowTitle("SETTING")
	s.window.ConnectCloseEvent(func(event *gui.QCloseEvent) {
		event.Ignore()
		s.window.Hide()
	})
	s.create()
	s.setLayout()
	s.setListener()
	s.updateData()

	if conFig.BlackIcon {
		sysproxy.SetSysProxy(conFig.HTTPHost, conFig.Socks5Host)
	}

	return s
}

func (s *setting) create() {
	// PROXY
	s.systemProxy = widgets.NewQCheckBox2("SET SYSTEM PROXY", nil)
	s.redirHostLabel = widgets.NewQLabel2("REDIR", nil, core.Qt__Widget)
	s.redirHostLineText = widgets.NewQLineEdit(nil)
	s.httpHostLabel = widgets.NewQLabel2("HTTP", nil, core.Qt__Widget)
	s.httpHostLineText = widgets.NewQLineEdit(nil)
	s.socks5HostLabel = widgets.NewQLabel2("SOCKS5", nil, core.Qt__Widget)
	s.socks5HostLineText = widgets.NewQLineEdit(nil)
	if runtime.GOOS == "windows" {
		s.redirHostLineText.SetDisabled(true)
	}

	// DNS
	s.dnsProxyCheckBox = widgets.NewQCheckBox2("PROXY", nil)
	s.dohCheckBox = widgets.NewQCheckBox2("ENABLED DOH", nil)
	s.dnsServerLabel = widgets.NewQLabel2("DNS", nil, core.Qt__Widget)
	s.dnsServerLineText = widgets.NewQLineEdit(nil)
	s.dnsSubNetLabel = widgets.NewQLabel2("SUBNET", nil, core.Qt__Widget)
	s.dnsSubNetLineText = widgets.NewQLineEdit(nil)

	// DIRECT DNS
	s.directDnsDOH = widgets.NewQCheckBox2("ENABLED DOH", nil)
	s.directDnsHost = widgets.NewQLineEdit(nil)
	s.directDnsHostLabel = widgets.NewQLabel2("HOST", nil, core.Qt__Widget)

	// BYPASS
	s.bypassCheckBox = widgets.NewQCheckBox2("BYPASS", nil)
	s.bypassLineText = widgets.NewQLineEdit(nil)

	// BUTTON
	s.applyButton = widgets.NewQPushButton2("APPLY", nil)
	s.reImportButton = widgets.NewQPushButton2("REIMPORT RULE", nil)
}

func (s *setting) setLayout() {
	localProxyGroup := widgets.NewQGroupBox2("PROXY", nil)
	localProxyLayout := widgets.NewQGridLayout2()
	localProxyLayout.AddWidget3(s.systemProxy, 0, 0, 1, 2, 0)
	localProxyLayout.AddWidget2(s.httpHostLabel, 1, 0, 0)
	localProxyLayout.AddWidget2(s.httpHostLineText, 1, 1, 0)
	localProxyLayout.AddWidget2(s.socks5HostLabel, 2, 0, 0)
	localProxyLayout.AddWidget2(s.socks5HostLineText, 2, 1, 0)
	localProxyLayout.AddWidget2(s.redirHostLabel, 3, 0, 0)
	localProxyLayout.AddWidget2(s.redirHostLineText, 3, 1, 0)
	localProxyGroup.SetLayout(localProxyLayout)

	dnsGroup := widgets.NewQGroupBox2("DNS", nil)
	dnsLayout := widgets.NewQGridLayout2()
	dnsLayout.AddWidget3(s.dohCheckBox, 0, 0, 1, 2, 0)
	dnsLayout.AddWidget2(s.dnsProxyCheckBox, 0, 2, 0)
	dnsLayout.AddWidget2(s.dnsServerLabel, 1, 0, 0)
	dnsLayout.AddWidget3(s.dnsServerLineText, 1, 1, 1, 2, 0)
	dnsLayout.AddWidget2(s.dnsSubNetLabel, 2, 0, 0)
	dnsLayout.AddWidget3(s.dnsSubNetLineText, 2, 1, 1, 2, 0)
	dnsGroup.SetLayout(dnsLayout)

	directDnsGroup := widgets.NewQGroupBox2("DIRECT DNS", nil)
	directDnsLayout := widgets.NewQGridLayout2()
	directDnsLayout.AddWidget3(s.directDnsDOH, 0, 0, 1, 2, 0)
	directDnsLayout.AddWidget2(s.directDnsHostLabel, 1, 0, 0)
	directDnsLayout.AddWidget2(s.directDnsHost, 1, 1, 0)
	directDnsGroup.SetLayout(directDnsLayout)

	bypassGroup := widgets.NewQGroupBox2("BYPASS", nil)
	bypassLayout := widgets.NewQGridLayout2()
	bypassLayout.AddWidget2(s.bypassCheckBox, 0, 0, 0)
	bypassLayout.AddWidget2(s.bypassLineText, 1, 0, 0)
	bypassGroup.SetLayout(bypassLayout)

	buttonGroup := widgets.NewQGroupBox(nil)
	buttonLayout := widgets.NewQGridLayout2()
	buttonLayout.AddWidget2(s.applyButton, 0, 0, 0)
	buttonLayout.AddWidget2(s.reImportButton, 1, 0, 0)
	buttonGroup.SetLayout(buttonLayout)

	windowLayout := widgets.NewQGridLayout2()
	windowLayout.AddWidget2(localProxyGroup, 0, 0, 0)
	windowLayout.AddWidget2(dnsGroup, 0, 1, 0)
	windowLayout.AddWidget2(bypassGroup, 1, 0, 0)
	windowLayout.AddWidget2(directDnsGroup, 1, 1, 0)
	windowLayout.AddWidget2(buttonGroup, 2, 0, 0)

	centralWidget := widgets.NewQWidget(s.window, 0)
	centralWidget.SetLayout(windowLayout)
	s.window.SetCentralWidget(centralWidget)
}

var (
	conFig *config.Setting
)

func (s *setting) updateData() {
	var err error
	conFig, err = apiC.GetConfig(context.Background(), &empty.Empty{})
	if err != nil {
		MessageBox(err.Error())
		return
	}
	s.systemProxy.SetChecked(conFig.BlackIcon)
	s.dohCheckBox.SetChecked(conFig.DOH)
	s.bypassCheckBox.SetChecked(conFig.Bypass)
	s.dnsProxyCheckBox.SetChecked(conFig.DNSProxy)
	s.redirHostLineText.SetText(conFig.RedirHost)
	s.httpHostLineText.SetText(conFig.HTTPHost)
	s.socks5HostLineText.SetText(conFig.Socks5Host)
	s.dnsServerLineText.SetText(conFig.DnsServer)
	s.bypassLineText.SetText(conFig.BypassFile)
	s.dnsSubNetLineText.SetText(conFig.DnsSubNet)
	s.directDnsHost.SetText(conFig.DirectDNS.Host)
	s.directDnsDOH.SetChecked(conFig.DirectDNS.DOH)
}

func (s *setting) setListener() {
	s.applyButton.ConnectClicked(s.applyCall)
	s.reImportButton.ConnectClicked(s.reimportCall)
	s.window.ConnectShowEvent(func(_ *gui.QShowEvent) { s.updateData() })
}

func (s *setting) applyCall(_ bool) {
	if conFig.BlackIcon != s.systemProxy.IsChecked() ||
		conFig.HTTPHost != s.httpHostLineText.Text() ||
		conFig.Socks5Host != s.socks5HostLineText.Text() {
		conFig.BlackIcon = s.systemProxy.IsChecked()
		if conFig.BlackIcon {
			sysproxy.SetSysProxy(s.httpHostLineText.Text(), s.socks5HostLineText.Text())
		} else {
			sysproxy.UnsetSysProxy()
		}
	}
	conFig.Bypass = s.bypassCheckBox.IsChecked()
	conFig.DOH = s.dohCheckBox.IsChecked()
	conFig.DNSProxy = s.dnsProxyCheckBox.IsChecked()
	conFig.DnsServer = s.dnsServerLineText.Text()
	conFig.DnsSubNet = s.dnsSubNetLineText.Text()
	//conFig.SsrPath = s.ssrPathLineText.Text()
	conFig.HTTPHost = s.httpHostLineText.Text()
	conFig.Socks5Host = s.socks5HostLineText.Text()
	conFig.RedirHost = s.redirHostLineText.Text()
	conFig.BypassFile = s.bypassLineText.Text()
	conFig.DirectDNS.Host = s.directDnsHost.Text()
	conFig.DirectDNS.DOH = s.directDnsDOH.IsChecked()
	_, err := apiC.SetConfig(context.Background(), conFig)
	if err != nil {
		MessageBox(err.Error())
	}
	s.updateData()
	MessageBox("Applied.")
}

func (s *setting) reimportCall(_ bool) {
	_, err := apiC.ReimportRule(context.Background(), &empty.Empty{})
	if err != nil {
		MessageBox(err.Error())
		return
	}
	MessageBox("Updated.")
}
