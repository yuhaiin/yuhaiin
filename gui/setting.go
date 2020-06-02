package gui

import (
	"github.com/Asutorufa/yuhaiin/config"
	"github.com/Asutorufa/yuhaiin/process"
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

	redirProxyAddressLabel   *widgets.QLabel
	httpAddressLabel         *widgets.QLabel
	socks5BypassAddressLabel *widgets.QLabel
	dnsServerLabel           *widgets.QLabel
	ssrPathLabel             *widgets.QLabel
	//BypassFileLabel          *widgets.QLabel

	redirProxyAddressLineText *widgets.QLineEdit
	httpAddressLineText       *widgets.QLineEdit
	socks5BypassLineText      *widgets.QLineEdit
	dnsServerLineText         *widgets.QLineEdit
	ssrPathLineText           *widgets.QLineEdit
	BypassFileLineText        *widgets.QLineEdit

	applyButton      *widgets.QPushButton
	updateRuleButton *widgets.QPushButton
}

func NewSettingWindow(parent *widgets.QMainWindow) *widgets.QMainWindow {
	s := setting{}
	s.parent = parent
	s.settingWindow = widgets.NewQMainWindow(nil, core.Qt__Window)
	s.settingWindow.SetWindowFlag(core.Qt__WindowMinimizeButtonHint, false)
	s.settingWindow.SetWindowFlag(core.Qt__WindowMaximizeButtonHint, false)
	s.settingWindow.SetFixedSize2(430, 330)
	s.settingWindow.SetWindowTitle("setting")
	s.settingWindow.ConnectCloseEvent(func(event *gui.QCloseEvent) {
		event.Ignore()
		s.settingWindow.Hide()
	})
	s.settingInit()
	s.setGeometry()
	s.setListener()
	s.extends()

	return s.settingWindow
}

func (s *setting) settingInit() {
	s.BlackIconCheckBox = widgets.NewQCheckBox2("Black Icon", s.settingWindow)
	s.DnsOverHttpsCheckBox = widgets.NewQCheckBox2("DOH", s.settingWindow)
	//httpProxyCheckBox := widgets.NewQCheckBox2("http proxy", sGui.settingWindow)
	s.bypassCheckBox = widgets.NewQCheckBox2("BYPASS", s.settingWindow)
	s.DnsOverHttpsProxyCheckBox = widgets.NewQCheckBox2("PROXY", s.settingWindow)
	s.redirProxyAddressLabel = widgets.NewQLabel2("REDIR", s.settingWindow, 0)
	s.redirProxyAddressLineText = widgets.NewQLineEdit(s.settingWindow)
	s.httpAddressLabel = widgets.NewQLabel2("HTTP", s.settingWindow, 0)
	s.httpAddressLineText = widgets.NewQLineEdit(s.settingWindow)
	s.socks5BypassAddressLabel = widgets.NewQLabel2("SOCKS5", s.settingWindow, 0)
	s.socks5BypassLineText = widgets.NewQLineEdit(s.settingWindow)
	s.dnsServerLabel = widgets.NewQLabel2("DNS", s.settingWindow, 0)
	s.dnsServerLineText = widgets.NewQLineEdit(s.settingWindow)
	s.ssrPathLabel = widgets.NewQLabel2("SSR PATH", s.settingWindow, 0)
	s.ssrPathLineText = widgets.NewQLineEdit(s.settingWindow)
	//s.BypassFileLabel = widgets.NewQLabel2("bypassFile", s.settingWindow, 0)
	s.BypassFileLineText = widgets.NewQLineEdit(s.settingWindow)
	s.applyButton = widgets.NewQPushButton2("apply", s.settingWindow)
	s.updateRuleButton = widgets.NewQPushButton2("Reimport Bypass Rule", s.settingWindow)
}

func (s *setting) setGeometry() {
	s.BlackIconCheckBox.SetGeometry(core.NewQRect2(core.NewQPoint2(10, 0), core.NewQPoint2(140, 30)))
	//httpProxyCheckBox.SetGeometry(core.NewQRect2(core.NewQPoint2(10, 40), core.NewQPoint2(130, 70)))
	s.redirProxyAddressLabel.SetGeometry(core.NewQRect2(core.NewQPoint2(10, 80), core.NewQPoint2(70, 110)))
	s.redirProxyAddressLineText.SetGeometry(core.NewQRect2(core.NewQPoint2(80, 80), core.NewQPoint2(210, 110)))
	s.httpAddressLabel.SetGeometry(core.NewQRect2(core.NewQPoint2(10, 120), core.NewQPoint2(70, 150)))
	s.httpAddressLineText.SetGeometry(core.NewQRect2(core.NewQPoint2(80, 120), core.NewQPoint2(210, 150)))
	s.socks5BypassAddressLabel.SetGeometry(core.NewQRect2(core.NewQPoint2(220, 120), core.NewQPoint2(290, 150)))
	s.socks5BypassLineText.SetGeometry(core.NewQRect2(core.NewQPoint2(300, 120), core.NewQPoint2(420, 150)))
	s.dnsServerLabel.SetGeometry(core.NewQRect2(core.NewQPoint2(10, 160), core.NewQPoint2(50, 190)))
	s.DnsOverHttpsCheckBox.SetGeometry(core.NewQRect2(core.NewQPoint2(60, 160), core.NewQPoint2(125, 190)))
	s.DnsOverHttpsProxyCheckBox.SetGeometry(core.NewQRect2(core.NewQPoint2(135, 160), core.NewQPoint2(220, 190)))
	s.dnsServerLineText.SetGeometry(core.NewQRect2(core.NewQPoint2(230, 160), core.NewQPoint2(420, 190)))
	s.ssrPathLabel.SetGeometry(core.NewQRect2(core.NewQPoint2(10, 200), core.NewQPoint2(90, 230)))
	s.ssrPathLineText.SetGeometry(core.NewQRect2(core.NewQPoint2(100, 200), core.NewQPoint2(420, 230)))
	s.bypassCheckBox.SetGeometry(core.NewQRect2(core.NewQPoint2(10, 240), core.NewQPoint2(105, 270)))
	//s.BypassFileLabel.SetGeometry(core.NewQRect2(core.NewQPoint2(10, 240), core.NewQPoint2(100, 270)))
	s.BypassFileLineText.SetGeometry(core.NewQRect2(core.NewQPoint2(115, 240), core.NewQPoint2(420, 270)))
	s.applyButton.SetGeometry(core.NewQRect2(core.NewQPoint2(10, 280), core.NewQPoint2(105, 310)))
	s.updateRuleButton.SetGeometry(core.NewQRect2(core.NewQPoint2(115, 280), core.NewQPoint2(300, 310)))

}
func (s *setting) setListener() {
	// Listen
	update := func() {
		conFig, err := config.SettingDecodeJSON()
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
	}

	applyClick := func(bool2 bool) {
		conFig, err := config.SettingDecodeJSON()
		if err != nil {
			MessageBox(err.Error())
			return
		}

		conFig.BlackIcon = s.BlackIconCheckBox.IsChecked()

		//conFig.HttpProxy = httpProxyCheckBox.IsChecked()

		isUpdateMode := false
		if conFig.Bypass != s.bypassCheckBox.IsChecked() {
			conFig.Bypass = s.bypassCheckBox.IsChecked()
			isUpdateMode = true
		}

		//isUpdateDNS := false
		if conFig.IsDNSOverHTTPS != s.DnsOverHttpsCheckBox.IsChecked() || conFig.DnsServer != s.dnsServerLineText.Text() || conFig.DNSAcrossProxy != s.DnsOverHttpsProxyCheckBox.IsChecked() {
			conFig.IsDNSOverHTTPS = s.DnsOverHttpsCheckBox.IsChecked()
			conFig.DNSAcrossProxy = s.DnsOverHttpsProxyCheckBox.IsChecked()
			conFig.DnsServer = s.dnsServerLineText.Text()
			//isUpdateDNS = true
			process.UpdateDNS(s.dnsServerLineText.Text())
		}

		isChangeNode := false
		if conFig.SsrPath != s.ssrPathLineText.Text() {
			conFig.SsrPath = s.ssrPathLineText.Text()
			isChangeNode = true
		}

		isUpdateListen := false
		if conFig.HttpProxyAddress != s.httpAddressLineText.Text() ||
			conFig.Socks5ProxyAddress != s.socks5BypassLineText.Text() ||
			conFig.RedirProxyAddress != s.redirProxyAddressLineText.Text() {

			conFig.HttpProxyAddress = s.httpAddressLineText.Text()
			conFig.Socks5ProxyAddress = s.socks5BypassLineText.Text()
			conFig.RedirProxyAddress = s.redirProxyAddressLineText.Text()
			isUpdateListen = true
		}

		isUpdateMatch := false
		if conFig.BypassFile != s.BypassFileLineText.Text() {
			conFig.BypassFile = s.BypassFileLineText.Text()
			isUpdateMatch = true
		}

		if err := config.SettingEnCodeJSON(conFig); err != nil {
			MessageBox(err.Error())
		}

		if isUpdateMode {
			if err := process.UpdateMode(); err != nil {
				MessageBox(err.Error())
				return
			}
		}

		if isChangeNode {
			if err := process.ChangeNode(); err != nil {
				MessageBox(err.Error())
				return
			}
		}

		if isUpdateListen {
			if err := process.UpdateListen(); err != nil {
				MessageBox(err.Error())
				return
			}
		}

		if isUpdateMatch {
			if err := process.UpdateMatch(); err != nil {
				MessageBox(err.Error())
				return
			}
		}

		update()

		MessageBox("Applied.")
	}

	// set Listener
	s.applyButton.ConnectClicked(applyClick)
	s.updateRuleButton.ConnectClicked(func(checked bool) {
		if err := process.UpdateMatch(); err != nil {
			MessageBox(err.Error())
			return
		}
		MessageBox("Updated.")
	})

	s.settingWindow.ConnectShowEvent(func(event *gui.QShowEvent) {
		update()
	})
}
