package gui

import (
	"github.com/Asutorufa/yuhaiin/config"
	"github.com/golang/protobuf/ptypes/empty"

	"github.com/therecipe/qt/core"
	"github.com/therecipe/qt/gui"
	"github.com/therecipe/qt/widgets"
)

type setting struct {
	settingWindow *widgets.QMainWindow
	parent        *widgets.QMainWindow

	BlackIconCheckBox         *widgets.QCheckBox
	DnsOverHttpsCheckBox      *widgets.QCheckBox
	bypassCheckBox            *widgets.QCheckBox
	DnsOverHttpsProxyCheckBox *widgets.QCheckBox
	directDnsIsDOH            *widgets.QCheckBox

	redirProxyAddressLabel   *widgets.QLabel
	httpAddressLabel         *widgets.QLabel
	socks5BypassAddressLabel *widgets.QLabel
	dnsServerLabel           *widgets.QLabel
	ssrPathLabel             *widgets.QLabel
	//BypassFileLabel          *widgets.QLabel
	dnsSubNetLabel     *widgets.QLabel
	directDnsHostLabel *widgets.QLabel

	redirProxyAddressLineText *widgets.QLineEdit
	httpAddressLineText       *widgets.QLineEdit
	socks5BypassLineText      *widgets.QLineEdit
	dnsServerLineText         *widgets.QLineEdit
	ssrPathLineText           *widgets.QLineEdit
	BypassFileLineText        *widgets.QLineEdit
	dnsSubNetLineText         *widgets.QLineEdit
	directDnsHost             *widgets.QLineEdit

	applyButton      *widgets.QPushButton
	updateRuleButton *widgets.QPushButton
}

func NewSettingWindow(parent *widgets.QMainWindow) *widgets.QMainWindow {
	s := setting{}
	s.parent = parent
	s.settingWindow = widgets.NewQMainWindow(nil, core.Qt__Window)
	s.settingWindow.SetWindowTitle("setting")
	s.settingWindow.ConnectCloseEvent(func(event *gui.QCloseEvent) {
		event.Ignore()
		s.settingWindow.Hide()
	})
	s.settingInit()
	s.setLayout()
	//s.setGeometry()
	s.setListener()
	s.extends()

	return s.settingWindow
}

func (s *setting) settingInit() {
	//httpProxyCheckBox := widgets.NewQCheckBox2("http proxy", sGui.settingWindow)
	s.bypassCheckBox = widgets.NewQCheckBox2("BYPASS", s.settingWindow)
	//s.BypassFileLabel = widgets.NewQLabel2("bypassFile", s.settingWindow, 0)
	s.BypassFileLineText = widgets.NewQLineEdit(s.settingWindow)

	s.redirProxyAddressLabel = widgets.NewQLabel2("REDIR", s.settingWindow, 0)
	s.redirProxyAddressLineText = widgets.NewQLineEdit(s.settingWindow)
	s.httpAddressLabel = widgets.NewQLabel2("HTTP", s.settingWindow, 0)
	s.httpAddressLineText = widgets.NewQLineEdit(s.settingWindow)
	s.socks5BypassAddressLabel = widgets.NewQLabel2("SOCKS5", s.settingWindow, 0)
	s.socks5BypassLineText = widgets.NewQLineEdit(s.settingWindow)

	s.DnsOverHttpsProxyCheckBox = widgets.NewQCheckBox2("PROXY", s.settingWindow)
	s.DnsOverHttpsCheckBox = widgets.NewQCheckBox2("ENABLED DOH", s.settingWindow)
	s.dnsServerLabel = widgets.NewQLabel2("DNS", s.settingWindow, 0)
	s.dnsServerLineText = widgets.NewQLineEdit(s.settingWindow)
	s.dnsSubNetLabel = widgets.NewQLabel2("SUBNET", nil, 0)
	s.dnsSubNetLineText = widgets.NewQLineEdit(nil)

	s.directDnsIsDOH = widgets.NewQCheckBox2("ENABLED DOH", nil)
	s.directDnsHost = widgets.NewQLineEdit(nil)
	s.directDnsHostLabel = widgets.NewQLabel2("HOST", nil, 0)

	s.BlackIconCheckBox = widgets.NewQCheckBox2("BLACK ICON", s.settingWindow)
	s.ssrPathLabel = widgets.NewQLabel2("SSR PATH", s.settingWindow, 0)
	s.ssrPathLineText = widgets.NewQLineEdit(s.settingWindow)

	s.applyButton = widgets.NewQPushButton2("apply", s.settingWindow)
	s.updateRuleButton = widgets.NewQPushButton2("Reimport Bypass Rule", nil)
}

func (s *setting) setLayout() {
	localProxyGroup := widgets.NewQGroupBox2("PROXY", nil)
	localProxyLayout := widgets.NewQGridLayout2()
	localProxyLayout.AddWidget2(s.httpAddressLabel, 0, 0, 0)
	localProxyLayout.AddWidget2(s.httpAddressLineText, 0, 1, 0)
	localProxyLayout.AddWidget2(s.socks5BypassAddressLabel, 1, 0, 0)
	localProxyLayout.AddWidget2(s.socks5BypassLineText, 1, 1, 0)
	localProxyLayout.AddWidget2(s.redirProxyAddressLabel, 2, 0, 0)
	localProxyLayout.AddWidget2(s.redirProxyAddressLineText, 2, 1, 0)
	localProxyGroup.SetLayout(localProxyLayout)

	dnsGroup := widgets.NewQGroupBox2("DNS", nil)
	dnsLayout := widgets.NewQGridLayout2()
	dnsLayout.AddWidget3(s.DnsOverHttpsCheckBox, 0, 0, 1, 2, 0)
	dnsLayout.AddWidget2(s.DnsOverHttpsProxyCheckBox, 0, 2, 0)
	dnsLayout.AddWidget2(s.dnsServerLabel, 1, 0, 0)
	dnsLayout.AddWidget3(s.dnsServerLineText, 1, 1, 1, 2, 0)
	dnsLayout.AddWidget2(s.dnsSubNetLabel, 2, 0, 0)
	dnsLayout.AddWidget3(s.dnsSubNetLineText, 2, 1, 1, 2, 0)
	dnsGroup.SetLayout(dnsLayout)

	directDnsGroup := widgets.NewQGroupBox2("DIRECT DNS", nil)
	directDnsLayout := widgets.NewQGridLayout2()
	directDnsLayout.AddWidget3(s.directDnsIsDOH, 0, 0, 1, 2, 0)
	directDnsLayout.AddWidget2(s.directDnsHostLabel, 1, 0, 0)
	directDnsLayout.AddWidget2(s.directDnsHost, 1, 1, 0)
	directDnsGroup.SetLayout(directDnsLayout)

	bypassGroup := widgets.NewQGroupBox2("BYPASS", nil)
	bypassLayout := widgets.NewQGridLayout2()
	bypassLayout.AddWidget2(s.bypassCheckBox, 0, 0, 0)
	bypassLayout.AddWidget2(s.BypassFileLineText, 1, 0, 0)
	bypassGroup.SetLayout(bypassLayout)

	othersGroup := widgets.NewQGroupBox2("OTHERS", nil)
	othersLayout := widgets.NewQGridLayout2()
	othersLayout.AddWidget3(s.BlackIconCheckBox, 0, 0, 1, 2, 0)
	othersLayout.AddWidget2(s.ssrPathLabel, 1, 0, 0)
	othersLayout.AddWidget2(s.ssrPathLineText, 1, 1, 0)
	othersGroup.SetLayout(othersLayout)

	buttonGroup := widgets.NewQGroupBox(nil)
	buttonLayout := widgets.NewQGridLayout2()
	buttonLayout.AddWidget2(s.applyButton, 0, 0, 0)
	buttonLayout.AddWidget2(s.updateRuleButton, 1, 0, 0)
	buttonGroup.SetLayout(buttonLayout)

	windowLayout := widgets.NewQGridLayout2()
	windowLayout.AddWidget2(localProxyGroup, 0, 0, 0)
	windowLayout.AddWidget2(dnsGroup, 0, 1, 0)
	windowLayout.AddWidget2(bypassGroup, 1, 0, 0)
	windowLayout.AddWidget2(othersGroup, 2, 1, 0)
	windowLayout.AddWidget2(directDnsGroup, 1, 1, 0)
	windowLayout.AddWidget2(buttonGroup, 2, 0, 0)

	centralWidget := widgets.NewQWidget(s.settingWindow, 0)
	centralWidget.SetLayout(windowLayout)
	s.settingWindow.SetCentralWidget(centralWidget)
}

var (
	conFig *config.Setting
)

func (s *setting) setListener() {
	// Listen
	update := func() {
		var err error
		conFig, err = apiC.GetConfig(apiCtx(), &empty.Empty{})
		if err != nil {
			MessageBox(err.Error())
			return
		}
		s.BlackIconCheckBox.SetChecked(conFig.BlackIcon)
		s.DnsOverHttpsCheckBox.SetChecked(conFig.IsDNSOverHTTPS)
		//httpProxyCheckBox.SetChecked(conFig.HttpProxy)
		s.bypassCheckBox.SetChecked(conFig.Bypass)
		s.DnsOverHttpsProxyCheckBox.SetChecked(conFig.DNSAcrossProxy)
		s.redirProxyAddressLineText.SetText(conFig.RedirProxyAddress)
		s.httpAddressLineText.SetText(conFig.HttpProxyAddress)
		s.socks5BypassLineText.SetText(conFig.Socks5ProxyAddress)
		s.dnsServerLineText.SetText(conFig.DnsServer)
		s.ssrPathLineText.SetText(conFig.SsrPath)
		s.BypassFileLineText.SetText(conFig.BypassFile)
		s.dnsSubNetLineText.SetText(conFig.DnsSubNet)
		s.directDnsHost.SetText(conFig.DirectDNS.Host)
		s.directDnsIsDOH.SetChecked(conFig.DirectDNS.DOH)
	}

	applyClick := func(bool2 bool) {
		//log.Println("apply start")
		conFig.BlackIcon = s.BlackIconCheckBox.IsChecked()
		//conFig.HttpProxy = httpProxyCheckBox.IsChecked()
		conFig.Bypass = s.bypassCheckBox.IsChecked()
		conFig.IsDNSOverHTTPS = s.DnsOverHttpsCheckBox.IsChecked()
		conFig.DNSAcrossProxy = s.DnsOverHttpsProxyCheckBox.IsChecked()
		conFig.DnsServer = s.dnsServerLineText.Text()
		conFig.DnsSubNet = s.dnsSubNetLineText.Text()
		conFig.SsrPath = s.ssrPathLineText.Text()
		conFig.HttpProxyAddress = s.httpAddressLineText.Text()
		conFig.Socks5ProxyAddress = s.socks5BypassLineText.Text()
		conFig.RedirProxyAddress = s.redirProxyAddressLineText.Text()
		conFig.BypassFile = s.BypassFileLineText.Text()
		conFig.DirectDNS.Host = s.directDnsHost.Text()
		conFig.DirectDNS.DOH = s.directDnsIsDOH.IsChecked()
		_, err := apiC.SetConfig(apiCtx(), conFig)
		if err != nil {
			MessageBox(err.Error())
		}
		update()
		MessageBox("Applied.")
	}

	// set Listener
	s.applyButton.ConnectClicked(applyClick)
	s.updateRuleButton.ConnectClicked(func(checked bool) {
		_, err := apiC.ReimportRule(apiCtx(), &empty.Empty{})
		if err != nil {
			MessageBox(err.Error())
			return
		}
		MessageBox("Updated.")
	})

	s.settingWindow.ConnectShowEvent(func(event *gui.QShowEvent) {
		update()
	})
}
