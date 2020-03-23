package gui

import (
	"github.com/Asutorufa/SsrMicroClient/config"
	"github.com/therecipe/qt/core"
	"github.com/therecipe/qt/gui"
	"github.com/therecipe/qt/widgets"
)

func (ssrMicroClientGUI *SsrMicroClientGUI) createSettingWindow() {
	ssrMicroClientGUI.settingWindow = widgets.NewQMainWindow(ssrMicroClientGUI.MainWindow, 0)
	ssrMicroClientGUI.settingWindow.SetFixedSize2(430, 330)
	ssrMicroClientGUI.settingWindow.SetWindowTitle("setting")
	ssrMicroClientGUI.settingWindow.ConnectCloseEvent(func(event *gui.QCloseEvent) {
		event.Ignore()
		ssrMicroClientGUI.settingWindow.Hide()
	})
	conFig, err := config.SettingDecodeJSON()
	if err != nil {
		ssrMicroClientGUI.MessageBox(err.Error())
		return
	}
	autoStartSsr := widgets.NewQCheckBox2("auto Start ssr", ssrMicroClientGUI.settingWindow)
	autoStartSsr.SetChecked(conFig.AutoStartSsr)
	autoStartSsr.SetGeometry(core.NewQRect2(core.NewQPoint2(10, 0), core.NewQPoint2(490, 30)))

	httpProxyCheckBox := widgets.NewQCheckBox2("http proxy", ssrMicroClientGUI.settingWindow)
	httpProxyCheckBox.SetDisabled(true)
	httpProxyCheckBox.SetChecked(conFig.HttpProxy)
	httpProxyCheckBox.SetGeometry(core.NewQRect2(core.NewQPoint2(10, 40), core.NewQPoint2(130, 70)))

	bypassCheckBox := widgets.NewQCheckBox2("bypass", ssrMicroClientGUI.settingWindow)
	bypassCheckBox.SetDisabled(true)
	bypassCheckBox.SetChecked(conFig.Bypass)
	bypassCheckBox.SetGeometry(core.NewQRect2(core.NewQPoint2(140, 40), core.NewQPoint2(220, 70)))

	DnsOverHttpsCheckBox := widgets.NewQCheckBox2("Use DNSOverHTTPS", ssrMicroClientGUI.settingWindow)
	DnsOverHttpsCheckBox.SetChecked(conFig.IsDNSOverHTTPS)
	DnsOverHttpsCheckBox.SetGeometry(core.NewQRect2(core.NewQPoint2(10, 80), core.NewQPoint2(200, 110)))

	DnsOverHttpsProxyCheckBox := widgets.NewQCheckBox2("DNS Over Proxy", ssrMicroClientGUI.settingWindow)
	DnsOverHttpsProxyCheckBox.SetChecked(conFig.DNSAcrossProxy)
	DnsOverHttpsProxyCheckBox.SetGeometry(core.NewQRect2(core.NewQPoint2(210, 80), core.NewQPoint2(400, 110)))

	httpAddressLabel := widgets.NewQLabel2("http", ssrMicroClientGUI.settingWindow, 0)
	httpAddressLabel.SetGeometry(core.NewQRect2(core.NewQPoint2(10, 120), core.NewQPoint2(70, 150)))
	httpAddressLineText := widgets.NewQLineEdit(ssrMicroClientGUI.settingWindow)
	httpAddressLineText.SetText(conFig.HttpProxyAddress)
	httpAddressLineText.SetGeometry(core.NewQRect2(core.NewQPoint2(80, 120), core.NewQPoint2(210, 150)))

	socks5BypassAddressLabel := widgets.NewQLabel2("socks5", ssrMicroClientGUI.settingWindow, 0)
	socks5BypassAddressLabel.SetGeometry(core.NewQRect2(core.NewQPoint2(220, 120), core.NewQPoint2(290, 150)))
	socks5BypassLineText := widgets.NewQLineEdit(ssrMicroClientGUI.settingWindow)
	socks5BypassLineText.SetText(conFig.Socks5ProxyAddress)
	socks5BypassLineText.SetGeometry(core.NewQRect2(core.NewQPoint2(300, 120), core.NewQPoint2(420, 150)))

	dnsServerLabel := widgets.NewQLabel2("DNS", ssrMicroClientGUI.settingWindow, 0)
	dnsServerLabel.SetGeometry(core.NewQRect2(core.NewQPoint2(10, 160), core.NewQPoint2(100, 190)))
	dnsServerLineText := widgets.NewQLineEdit(ssrMicroClientGUI.settingWindow)
	dnsServerLineText.SetText(conFig.DnsServer)
	dnsServerLineText.SetGeometry(core.NewQRect2(core.NewQPoint2(110, 160), core.NewQPoint2(420, 190)))

	ssrPathLabel := widgets.NewQLabel2("ssrPath", ssrMicroClientGUI.settingWindow, 0)
	ssrPathLabel.SetGeometry(core.NewQRect2(core.NewQPoint2(10, 200), core.NewQPoint2(100, 230)))
	ssrPathLineText := widgets.NewQLineEdit(ssrMicroClientGUI.settingWindow)
	ssrPathLineText.SetText(conFig.SsrPath)
	ssrPathLineText.SetGeometry(core.NewQRect2(core.NewQPoint2(110, 200), core.NewQPoint2(420, 230)))

	BypassFileLabel := widgets.NewQLabel2("bypassFilePath", ssrMicroClientGUI.settingWindow, 0)
	BypassFileLabel.SetGeometry(core.NewQRect2(core.NewQPoint2(10, 240), core.NewQPoint2(100, 270)))
	BypassFileLineText := widgets.NewQLineEdit(ssrMicroClientGUI.settingWindow)
	BypassFileLineText.SetText(conFig.BypassFile)
	BypassFileLineText.SetGeometry(core.NewQRect2(core.NewQPoint2(110, 240), core.NewQPoint2(420, 270)))

	applyButton := widgets.NewQPushButton2("apply", ssrMicroClientGUI.settingWindow)
	applyButton.ConnectClicked(func(bool2 bool) {
		conFig, err := config.SettingDecodeJSON()
		if err != nil {
			ssrMicroClientGUI.MessageBox(err.Error())
			return
		}

		conFig.AutoStartSsr = autoStartSsr.IsChecked()
		conFig.HttpProxy = httpProxyCheckBox.IsChecked()
		conFig.Bypass = bypassCheckBox.IsChecked()

		if conFig.IsDNSOverHTTPS != DnsOverHttpsCheckBox.IsChecked() || conFig.DnsServer != dnsServerLineText.Text() {
			conFig.IsDNSOverHTTPS = DnsOverHttpsCheckBox.IsChecked()
			conFig.DnsServer = dnsServerLineText.Text()
			if err := config.SettingEnCodeJSON(conFig); err != nil {
				ssrMicroClientGUI.MessageBox(err.Error())
				return
			}
			if err := ssrMicroClientGUI.control.Match.UpdateDNS(); err != nil {
				ssrMicroClientGUI.MessageBox(err.Error())
				return
			}
		}
		if conFig.SsrPath != ssrPathLineText.Text() {
			conFig.SsrPath = ssrPathLineText.Text()
			if err := config.SettingEnCodeJSON(conFig); err != nil {
				ssrMicroClientGUI.MessageBox(err.Error())
				return
			}
			if err := ssrMicroClientGUI.control.ChangeNode(); err != nil {
				ssrMicroClientGUI.MessageBox(err.Error())
				return
			}

		}
		if conFig.HttpProxyAddress != httpAddressLineText.Text() || conFig.Socks5ProxyAddress != socks5BypassLineText.Text() {
			conFig.HttpProxyAddress = httpAddressLineText.Text()
			conFig.Socks5ProxyAddress = socks5BypassLineText.Text()
			if err := config.SettingEnCodeJSON(conFig); err != nil {
				ssrMicroClientGUI.MessageBox(err.Error())
				return
			}
			ssrMicroClientGUI.control.OutBound.Restart()
		}
		if conFig.BypassFile != BypassFileLineText.Text() {
			defer ssrMicroClientGUI.MessageBox("Change Bypass file,Please restart software to go into effect.")
			conFig.BypassFile = BypassFileLineText.Text()
		}
		if err := config.SettingEnCodeJSON(conFig); err != nil {
			ssrMicroClientGUI.MessageBox(err.Error())
		}
	})

	applyButton.SetGeometry(core.NewQRect2(core.NewQPoint2(10, 280), core.NewQPoint2(90, 310)))

	ssrMicroClientGUI.settingWindow.ConnectCloseEvent(func(event *gui.QCloseEvent) {
		ssrMicroClientGUI.settingWindow.Close()
	})
}
