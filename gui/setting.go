package gui

import (
	"github.com/Asutorufa/yuhaiin/config"
	"github.com/Asutorufa/yuhaiin/process"
	"github.com/therecipe/qt/core"
	"github.com/therecipe/qt/gui"
	"github.com/therecipe/qt/widgets"
)

func (sGui *SGui) createSettingWindow() {
	sGui.settingWindow = widgets.NewQMainWindow(sGui.MainWindow, 0)
	sGui.settingWindow.SetFixedSize2(430, 330)
	sGui.settingWindow.SetWindowTitle("setting")
	sGui.settingWindow.ConnectCloseEvent(func(event *gui.QCloseEvent) {
		event.Ignore()
		sGui.settingWindow.Hide()
	})

	// UI
	autoStartSsr := widgets.NewQCheckBox2("auto Start ssr", sGui.settingWindow)
	autoStartSsr.SetGeometry(core.NewQRect2(core.NewQPoint2(10, 0), core.NewQPoint2(140, 30)))

	DnsOverHttpsCheckBox := widgets.NewQCheckBox2("Use DNSOverHTTPS", sGui.settingWindow)
	DnsOverHttpsCheckBox.SetGeometry(core.NewQRect2(core.NewQPoint2(150, 0), core.NewQPoint2(430, 30)))

	httpProxyCheckBox := widgets.NewQCheckBox2("http proxy", sGui.settingWindow)
	httpProxyCheckBox.SetDisabled(true)
	httpProxyCheckBox.SetGeometry(core.NewQRect2(core.NewQPoint2(10, 40), core.NewQPoint2(130, 70)))

	bypassCheckBox := widgets.NewQCheckBox2("bypass", sGui.settingWindow)
	bypassCheckBox.SetGeometry(core.NewQRect2(core.NewQPoint2(140, 40), core.NewQPoint2(220, 70)))

	DnsOverHttpsProxyCheckBox := widgets.NewQCheckBox2("DNS Over Proxy", sGui.settingWindow)
	DnsOverHttpsProxyCheckBox.SetGeometry(core.NewQRect2(core.NewQPoint2(230, 40), core.NewQPoint2(400, 70)))

	redirProxyAddressLabel := widgets.NewQLabel2("redir", sGui.settingWindow, 0)
	redirProxyAddressLabel.SetGeometry(core.NewQRect2(core.NewQPoint2(10, 80), core.NewQPoint2(70, 110)))
	redirProxyAddressLineText := widgets.NewQLineEdit(sGui.settingWindow)
	redirProxyAddressLineText.SetGeometry(core.NewQRect2(core.NewQPoint2(80, 80), core.NewQPoint2(210, 110)))

	httpAddressLabel := widgets.NewQLabel2("http", sGui.settingWindow, 0)
	httpAddressLabel.SetGeometry(core.NewQRect2(core.NewQPoint2(10, 120), core.NewQPoint2(70, 150)))
	httpAddressLineText := widgets.NewQLineEdit(sGui.settingWindow)
	httpAddressLineText.SetGeometry(core.NewQRect2(core.NewQPoint2(80, 120), core.NewQPoint2(210, 150)))

	socks5BypassAddressLabel := widgets.NewQLabel2("socks5", sGui.settingWindow, 0)
	socks5BypassAddressLabel.SetGeometry(core.NewQRect2(core.NewQPoint2(220, 120), core.NewQPoint2(290, 150)))
	socks5BypassLineText := widgets.NewQLineEdit(sGui.settingWindow)
	socks5BypassLineText.SetGeometry(core.NewQRect2(core.NewQPoint2(300, 120), core.NewQPoint2(420, 150)))

	dnsServerLabel := widgets.NewQLabel2("DNS", sGui.settingWindow, 0)
	dnsServerLabel.SetGeometry(core.NewQRect2(core.NewQPoint2(10, 160), core.NewQPoint2(100, 190)))
	dnsServerLineText := widgets.NewQLineEdit(sGui.settingWindow)
	dnsServerLineText.SetGeometry(core.NewQRect2(core.NewQPoint2(110, 160), core.NewQPoint2(420, 190)))

	ssrPathLabel := widgets.NewQLabel2("ssrPath", sGui.settingWindow, 0)
	ssrPathLabel.SetGeometry(core.NewQRect2(core.NewQPoint2(10, 200), core.NewQPoint2(100, 230)))
	ssrPathLineText := widgets.NewQLineEdit(sGui.settingWindow)
	ssrPathLineText.SetGeometry(core.NewQRect2(core.NewQPoint2(110, 200), core.NewQPoint2(420, 230)))

	BypassFileLabel := widgets.NewQLabel2("bypassFilePath", sGui.settingWindow, 0)
	BypassFileLabel.SetGeometry(core.NewQRect2(core.NewQPoint2(10, 240), core.NewQPoint2(100, 270)))
	BypassFileLineText := widgets.NewQLineEdit(sGui.settingWindow)
	BypassFileLineText.SetGeometry(core.NewQRect2(core.NewQPoint2(110, 240), core.NewQPoint2(420, 270)))

	applyButton := widgets.NewQPushButton2("apply", sGui.settingWindow)
	applyButton.SetGeometry(core.NewQRect2(core.NewQPoint2(10, 280), core.NewQPoint2(90, 310)))

	updateRuleButton := widgets.NewQPushButton2("Reimport Bypass Rule", sGui.settingWindow)
	updateRuleButton.SetGeometry(core.NewQRect2(core.NewQPoint2(100, 280), core.NewQPoint2(300, 310)))

	// Listen
	update := func() {
		conFig, err := config.SettingDecodeJSON()
		if err != nil {
			sGui.MessageBox(err.Error())
			return
		}
		autoStartSsr.SetChecked(conFig.AutoStartSsr)
		DnsOverHttpsCheckBox.SetChecked(conFig.IsDNSOverHTTPS)
		httpProxyCheckBox.SetChecked(conFig.HttpProxy)
		bypassCheckBox.SetChecked(conFig.Bypass)
		DnsOverHttpsProxyCheckBox.SetChecked(conFig.DNSAcrossProxy)
		redirProxyAddressLineText.SetText(conFig.RedirProxyAddress)
		httpAddressLineText.SetText(conFig.HttpProxyAddress)
		socks5BypassLineText.SetText(conFig.Socks5ProxyAddress)
		dnsServerLineText.SetText(conFig.DnsServer)
		ssrPathLineText.SetText(conFig.SsrPath)
		BypassFileLineText.SetText(conFig.BypassFile)
	}

	applyClick := func(bool2 bool) {
		conFig, err := config.SettingDecodeJSON()
		if err != nil {
			sGui.MessageBox(err.Error())
			return
		}

		conFig.AutoStartSsr = autoStartSsr.IsChecked()
		conFig.HttpProxy = httpProxyCheckBox.IsChecked()

		isUpdateMode := false
		if conFig.Bypass != bypassCheckBox.IsChecked() {
			conFig.Bypass = bypassCheckBox.IsChecked()
			isUpdateMode = true
		}

		isUpdateDNS := false
		if conFig.IsDNSOverHTTPS != DnsOverHttpsCheckBox.IsChecked() || conFig.DnsServer != dnsServerLineText.Text() || conFig.DNSAcrossProxy != DnsOverHttpsProxyCheckBox.IsChecked() {
			conFig.IsDNSOverHTTPS = DnsOverHttpsCheckBox.IsChecked()
			conFig.DNSAcrossProxy = DnsOverHttpsProxyCheckBox.IsChecked()
			conFig.DnsServer = dnsServerLineText.Text()
			isUpdateDNS = true
		}

		isChangeNode := false
		if conFig.SsrPath != ssrPathLineText.Text() {
			conFig.SsrPath = ssrPathLineText.Text()
			isChangeNode = true
		}

		isUpdateListen := false
		if conFig.HttpProxyAddress != httpAddressLineText.Text() ||
			conFig.Socks5ProxyAddress != socks5BypassLineText.Text() ||
			conFig.RedirProxyAddress != redirProxyAddressLineText.Text() {

			conFig.HttpProxyAddress = httpAddressLineText.Text()
			conFig.Socks5ProxyAddress = socks5BypassLineText.Text()
			conFig.RedirProxyAddress = redirProxyAddressLineText.Text()
			isUpdateListen = true
		}

		isUpdateMatch := false
		if conFig.BypassFile != BypassFileLineText.Text() {
			conFig.BypassFile = BypassFileLineText.Text()
			isUpdateMatch = true
		}

		if err := config.SettingEnCodeJSON(conFig); err != nil {
			sGui.MessageBox(err.Error())
		}

		if isUpdateMode {
			if err := process.UpdateMode(); err != nil {
				sGui.MessageBox(err.Error())
				return
			}
		}

		if isUpdateDNS {
			if err := process.UpdateDNS(); err != nil {
				sGui.MessageBox(err.Error())
				return
			}
		}

		if isChangeNode {
			if err := process.ChangeNode(); err != nil {
				sGui.MessageBox(err.Error())
				return
			}
		}

		if isUpdateListen {
			if err := process.UpdateListen(); err != nil {
				sGui.MessageBox(err.Error())
				return
			}
		}

		if isUpdateMatch {
			if err := process.UpdateMatch(); err != nil {
				sGui.MessageBox(err.Error())
				return
			}
		}

		update()

		sGui.MessageBox("Applied.")
	}

	// set Listener
	applyButton.ConnectClicked(applyClick)
	updateRuleButton.ConnectClicked(func(checked bool) {
		if err := process.UpdateMatch(); err != nil {
			sGui.MessageBox(err.Error())
			return
		}
		sGui.MessageBox("Updated.")
	})

	sGui.settingWindow.ConnectShowEvent(func(event *gui.QShowEvent) {
		update()
	})
}
