package gui

import (
	"github.com/Asutorufa/yuhaiin/config"
	ServerControl "github.com/Asutorufa/yuhaiin/process/control"
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
	conFig, err := config.SettingDecodeJSON()
	if err != nil {
		sGui.MessageBox(err.Error())
		return
	}
	autoStartSsr := widgets.NewQCheckBox2("auto Start ssr", sGui.settingWindow)
	autoStartSsr.SetChecked(conFig.AutoStartSsr)
	autoStartSsr.SetGeometry(core.NewQRect2(core.NewQPoint2(10, 0), core.NewQPoint2(140, 30)))

	DnsOverHttpsCheckBox := widgets.NewQCheckBox2("Use DNSOverHTTPS", sGui.settingWindow)
	DnsOverHttpsCheckBox.SetChecked(conFig.IsDNSOverHTTPS)
	DnsOverHttpsCheckBox.SetGeometry(core.NewQRect2(core.NewQPoint2(150, 0), core.NewQPoint2(430, 30)))

	httpProxyCheckBox := widgets.NewQCheckBox2("http proxy", sGui.settingWindow)
	httpProxyCheckBox.SetDisabled(true)
	httpProxyCheckBox.SetChecked(conFig.HttpProxy)
	httpProxyCheckBox.SetGeometry(core.NewQRect2(core.NewQPoint2(10, 40), core.NewQPoint2(130, 70)))

	bypassCheckBox := widgets.NewQCheckBox2("bypass", sGui.settingWindow)
	bypassCheckBox.SetDisabled(true)
	bypassCheckBox.SetChecked(conFig.Bypass)
	bypassCheckBox.SetGeometry(core.NewQRect2(core.NewQPoint2(140, 40), core.NewQPoint2(220, 70)))

	DnsOverHttpsProxyCheckBox := widgets.NewQCheckBox2("DNS Over Proxy", sGui.settingWindow)
	DnsOverHttpsProxyCheckBox.SetChecked(conFig.DNSAcrossProxy)
	DnsOverHttpsProxyCheckBox.SetGeometry(core.NewQRect2(core.NewQPoint2(230, 40), core.NewQPoint2(400, 70)))

	redirProxyAddressLabel := widgets.NewQLabel2("redir", sGui.settingWindow, 0)
	redirProxyAddressLabel.SetGeometry(core.NewQRect2(core.NewQPoint2(10, 80), core.NewQPoint2(70, 110)))
	redirProxyAddressLineText := widgets.NewQLineEdit(sGui.settingWindow)
	redirProxyAddressLineText.SetText(conFig.RedirProxyAddress)
	redirProxyAddressLineText.SetGeometry(core.NewQRect2(core.NewQPoint2(80, 80), core.NewQPoint2(210, 110)))

	httpAddressLabel := widgets.NewQLabel2("http", sGui.settingWindow, 0)
	httpAddressLabel.SetGeometry(core.NewQRect2(core.NewQPoint2(10, 120), core.NewQPoint2(70, 150)))
	httpAddressLineText := widgets.NewQLineEdit(sGui.settingWindow)
	httpAddressLineText.SetText(conFig.HttpProxyAddress)
	httpAddressLineText.SetGeometry(core.NewQRect2(core.NewQPoint2(80, 120), core.NewQPoint2(210, 150)))

	socks5BypassAddressLabel := widgets.NewQLabel2("socks5", sGui.settingWindow, 0)
	socks5BypassAddressLabel.SetGeometry(core.NewQRect2(core.NewQPoint2(220, 120), core.NewQPoint2(290, 150)))
	socks5BypassLineText := widgets.NewQLineEdit(sGui.settingWindow)
	socks5BypassLineText.SetText(conFig.Socks5ProxyAddress)
	socks5BypassLineText.SetGeometry(core.NewQRect2(core.NewQPoint2(300, 120), core.NewQPoint2(420, 150)))

	dnsServerLabel := widgets.NewQLabel2("DNS", sGui.settingWindow, 0)
	dnsServerLabel.SetGeometry(core.NewQRect2(core.NewQPoint2(10, 160), core.NewQPoint2(100, 190)))
	dnsServerLineText := widgets.NewQLineEdit(sGui.settingWindow)
	dnsServerLineText.SetText(conFig.DnsServer)
	dnsServerLineText.SetGeometry(core.NewQRect2(core.NewQPoint2(110, 160), core.NewQPoint2(420, 190)))

	ssrPathLabel := widgets.NewQLabel2("ssrPath", sGui.settingWindow, 0)
	ssrPathLabel.SetGeometry(core.NewQRect2(core.NewQPoint2(10, 200), core.NewQPoint2(100, 230)))
	ssrPathLineText := widgets.NewQLineEdit(sGui.settingWindow)
	ssrPathLineText.SetText(conFig.SsrPath)
	ssrPathLineText.SetGeometry(core.NewQRect2(core.NewQPoint2(110, 200), core.NewQPoint2(420, 230)))

	BypassFileLabel := widgets.NewQLabel2("bypassFilePath", sGui.settingWindow, 0)
	BypassFileLabel.SetGeometry(core.NewQRect2(core.NewQPoint2(10, 240), core.NewQPoint2(100, 270)))
	BypassFileLineText := widgets.NewQLineEdit(sGui.settingWindow)
	BypassFileLineText.SetText(conFig.BypassFile)
	BypassFileLineText.SetGeometry(core.NewQRect2(core.NewQPoint2(110, 240), core.NewQPoint2(420, 270)))

	applyButton := widgets.NewQPushButton2("apply", sGui.settingWindow)
	applyButton.ConnectClicked(func(bool2 bool) {
		conFig, err := config.SettingDecodeJSON()
		if err != nil {
			sGui.MessageBox(err.Error())
			return
		}

		conFig.AutoStartSsr = autoStartSsr.IsChecked()
		conFig.HttpProxy = httpProxyCheckBox.IsChecked()
		conFig.Bypass = bypassCheckBox.IsChecked()

		if conFig.IsDNSOverHTTPS != DnsOverHttpsCheckBox.IsChecked() || conFig.DnsServer != dnsServerLineText.Text() {
			conFig.IsDNSOverHTTPS = DnsOverHttpsCheckBox.IsChecked()
			conFig.DnsServer = dnsServerLineText.Text()
			if err := config.SettingEnCodeJSON(conFig); err != nil {
				sGui.MessageBox(err.Error())
				return
			}
			if err := ServerControl.UpdateDNS(); err != nil {
				sGui.MessageBox(err.Error())
				return
			}
		}
		if conFig.SsrPath != ssrPathLineText.Text() {
			conFig.SsrPath = ssrPathLineText.Text()
			if err := config.SettingEnCodeJSON(conFig); err != nil {
				sGui.MessageBox(err.Error())
				return
			}
			if err := ServerControl.ChangeNode(); err != nil {
				sGui.MessageBox(err.Error())
				return
			}
		}

		if conFig.HttpProxyAddress != httpAddressLineText.Text() ||
			conFig.Socks5ProxyAddress != socks5BypassLineText.Text() ||
			conFig.RedirProxyAddress != redirProxyAddressLineText.Text() {

			conFig.HttpProxyAddress = httpAddressLineText.Text()
			conFig.Socks5ProxyAddress = socks5BypassLineText.Text()
			conFig.RedirProxyAddress = redirProxyAddressLineText.Text()
			if err := config.SettingEnCodeJSON(conFig); err != nil {
				sGui.MessageBox(err.Error())
				return
			}
			if err := ServerControl.UpdateListen(); err != nil {
				sGui.MessageBox(err.Error())
				return
			}
		}
		if conFig.BypassFile != BypassFileLineText.Text() {
			defer sGui.MessageBox("Change Bypass file,Please restart software to go into effect.")
			conFig.BypassFile = BypassFileLineText.Text()
		}
		if err := config.SettingEnCodeJSON(conFig); err != nil {
			sGui.MessageBox(err.Error())
		}
	})

	applyButton.SetGeometry(core.NewQRect2(core.NewQPoint2(10, 280), core.NewQPoint2(90, 310)))

	sGui.settingWindow.ConnectCloseEvent(func(event *gui.QCloseEvent) {
		sGui.settingWindow.Close()
	})
}
