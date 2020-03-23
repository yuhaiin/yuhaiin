package gui

import (
	"github.com/Asutorufa/SsrMicroClient/subscr"
	"github.com/therecipe/qt/core"
	"github.com/therecipe/qt/gui"
	"github.com/therecipe/qt/widgets"
)

func (sGui *SGui) createSubscriptionWindow() {
	sGui.subscriptionWindow = widgets.NewQMainWindow(sGui.MainWindow, 0)
	sGui.subscriptionWindow.SetFixedSize2(700, 100)
	sGui.subscriptionWindow.SetWindowTitle("subscription")
	sGui.subscriptionWindow.ConnectCloseEvent(func(event *gui.QCloseEvent) {
		event.Ignore()
		sGui.subscriptionWindow.Hide()
	})

	subLabel := widgets.NewQLabel2("subscription", sGui.subscriptionWindow, core.Qt__WindowType(0x00000000))
	subLabel.SetGeometry(core.NewQRect2(core.NewQPoint2(10, 10), core.NewQPoint2(130, 40)))
	subCombobox := widgets.NewQComboBox(sGui.subscriptionWindow)
	var link []string
	subRefresh := func() {
		subCombobox.Clear()
		var err error
		link, err = subscr.GetLink()
		if err != nil {
			sGui.MessageBox(err.Error())
		}
		subCombobox.AddItems(link)
	}
	subRefresh()
	subCombobox.SetGeometry(core.NewQRect2(core.NewQPoint2(115, 10), core.NewQPoint2(600, 40)))

	deleteButton := widgets.NewQPushButton2("delete", sGui.subscriptionWindow)
	deleteButton.ConnectClicked(func(bool2 bool) {
		linkToDelete := subCombobox.CurrentText()
		if err := subscr.RemoveLinkJSON(linkToDelete); err != nil {
			sGui.MessageBox(err.Error())
		}
		subRefresh()
	})
	deleteButton.SetGeometry(core.NewQRect2(core.NewQPoint2(610, 10), core.NewQPoint2(690, 40)))

	lineText := widgets.NewQLineEdit(sGui.subscriptionWindow)
	lineText.SetGeometry(core.NewQRect2(core.NewQPoint2(115, 50), core.NewQPoint2(600, 80)))

	addButton := widgets.NewQPushButton2("add", sGui.subscriptionWindow)
	addButton.ConnectClicked(func(bool2 bool) {
		linkToAdd := lineText.Text()
		if linkToAdd == "" {
			return
		}
		for _, linkExisted := range link {
			if linkExisted == linkToAdd {
				return
			}
		}
		if err := subscr.AddLinkJSON(linkToAdd); err != nil {
			sGui.MessageBox(err.Error())
			return
		}
		subRefresh()
	})
	addButton.SetGeometry(core.NewQRect2(core.NewQPoint2(610, 50), core.NewQPoint2(690, 80)))

	sGui.subscriptionWindow.ConnectCloseEvent(func(event *gui.QCloseEvent) {
		sGui.subscriptionWindow.Close()
	})
}
