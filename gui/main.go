package gui

import (
	"context"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/Asutorufa/yuhaiin/api"
	"github.com/golang/protobuf/ptypes/empty"
	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/therecipe/qt/core"
	"github.com/therecipe/qt/gui"
	"github.com/therecipe/qt/widgets"
)

type mainWindow struct {
	mainWindow      *widgets.QMainWindow
	statusLabel2    *widgets.QLabel
	nowNodeLabel    *widgets.QLabel
	nowNodeLabel2   *widgets.QLabel
	groupLabel      *widgets.QLabel
	groupCombobox   *widgets.QComboBox
	nodeLabel       *widgets.QLabel
	nodeCombobox    *widgets.QComboBox
	startButton     *widgets.QPushButton
	latencyLabel    *widgets.QLabel
	latencyLabel2   *widgets.QLabel
	latencyButton   *widgets.QPushButton
	subButton       *widgets.QPushButton
	subUpdateButton *widgets.QPushButton
	settingButton   *widgets.QPushButton

	menuBar *widgets.QMenuBar
}

func NewMainWindow(sGui *SGui) *widgets.QMainWindow {
	m := &mainWindow{}
	m.mainWindow = widgets.NewQMainWindow(nil, core.Qt__Window)
	m.mainWindow.SetWindowFlag(core.Qt__WindowSystemMenuHint, true)
	m.mainWindow.SetWindowTitle("yuhaiin")

	menuBar := widgets.NewQMenuBar(m.mainWindow)
	menuBar.SetFixedWidth(m.mainWindow.Width())
	mainMenu := menuBar.AddMenu2("Yuhaiin")
	settingMenu := mainMenu.AddAction("Settings...")
	settingMenu.ConnectTriggered(func(bool2 bool) { sGui.openWindow(sGui.settingWindow) })
	exitMenu := mainMenu.AddAction("Exit")
	exitMenu.ConnectTriggered(func(checked bool) { sGui.App.Quit() })
	subMenuGroup := menuBar.AddMenu2("Subscribe")
	subUpdate := subMenuGroup.AddAction("Update")
	subUpdate.ConnectTriggered(func(checked bool) { m.subUpdate() })
	subSetting := subMenuGroup.AddAction("Edit")
	subSetting.ConnectTriggered(func(checked bool) { sGui.openWindow(sGui.subscriptionWindow) })
	aboutMenu := menuBar.AddMenu2("About")
	githubAbout := aboutMenu.AddAction("Github")
	githubAbout.ConnectTriggered(func(checked bool) {
		gui.QDesktopServices_OpenUrl(core.NewQUrl3("https://github.com/Asutorufa/yuhaiin", core.QUrl__TolerantMode))
	})
	authorAbout := aboutMenu.AddAction("Author: Asutorufa")
	authorAbout.ConnectTriggered(func(checked bool) {
		gui.QDesktopServices_OpenUrl(core.NewQUrl3("https://github.com/Asutorufa", core.QUrl__TolerantMode))
	})
	aboutMenu.AddSeparator()
	aboutMenu.AddAction("Version: 0.2.11.5.Beta")
	menuBar.AdjustSize()
	m.mainWindow.SetMenuBar(menuBar)

	m.Init()
	m.setLayout()
	//m.setGeometry()
	m.setListener()

	return m.mainWindow
}

func (m *mainWindow) Init() {
	m.statusLabel2 = widgets.NewQLabel2("", m.mainWindow, core.Qt__WindowType(0x00000000))
	m.nowNodeLabel = widgets.NewQLabel2("Now Use", m.mainWindow, core.Qt__WindowType(0x00000000))
	m.nowNodeLabel2 = widgets.NewQLabel2("", m.mainWindow, core.Qt__WindowType(0x00000000))
	m.groupLabel = widgets.NewQLabel2("Group", m.mainWindow, core.Qt__WindowType(0x00000000))
	m.groupCombobox = widgets.NewQComboBox(m.mainWindow)
	m.nodeLabel = widgets.NewQLabel2("Node", m.mainWindow, core.Qt__WindowType(0x00000000))
	m.nodeCombobox = widgets.NewQComboBox(m.mainWindow)
	m.startButton = widgets.NewQPushButton2("Use", m.mainWindow)
	m.latencyLabel = widgets.NewQLabel2("Latency", m.mainWindow, core.Qt__WindowType(0x00000000))
	m.latencyLabel2 = widgets.NewQLabel2("", m.mainWindow, core.Qt__WindowType(0x00000000))
	m.latencyButton = widgets.NewQPushButton2("Test", m.mainWindow)
}

func (m *mainWindow) setLayout() {
	windowLayout := widgets.NewQGridLayout2()
	windowLayout.AddWidget3(m.statusLabel2, 0, 0, 1, 3, 0)
	windowLayout.AddWidget2(m.nowNodeLabel, 1, 0, 0)
	windowLayout.AddWidget2(m.nowNodeLabel2, 1, 1, 0)
	windowLayout.AddWidget2(m.groupLabel, 2, 0, 0)
	windowLayout.AddWidget2(m.groupCombobox, 2, 1, 0)
	windowLayout.AddWidget2(m.nodeLabel, 3, 0, 0)
	windowLayout.AddWidget2(m.nodeCombobox, 3, 1, 0)
	windowLayout.AddWidget2(m.startButton, 3, 2, 0)
	windowLayout.AddWidget2(m.latencyLabel, 4, 0, 0)
	windowLayout.AddWidget2(m.latencyLabel2, 4, 1, 0)
	windowLayout.AddWidget2(m.latencyButton, 4, 2, 0)

	centralWidget := widgets.NewQWidget(m.mainWindow, 0)
	centralWidget.SetLayout(windowLayout)
	m.mainWindow.SetCentralWidget(centralWidget)
}

func (m *mainWindow) refresh() {
	group, err := apiC.GetGroup(apiCtx(), &empty.Empty{})
	if err != nil {
		MessageBox(err.Error())
		return
	}
	m.groupCombobox.Clear()
	m.groupCombobox.AddItems(group.Value)
	node, err := apiC.GetNode(apiCtx(), &wrappers.StringValue{Value: m.groupCombobox.CurrentText()})
	if err != nil {
		MessageBox(err.Error())
		return
	}
	m.nodeCombobox.Clear()
	m.nodeCombobox.AddItems(node.Value)

	nowNodeAndGroup, err := apiC.GetNowGroupAndName(apiCtx(), &empty.Empty{})
	if err != nil {
		MessageBox(err.Error())
		return
	}

	m.groupCombobox.SetCurrentText(nowNodeAndGroup.Group)
	m.nodeCombobox.SetCurrentText(nowNodeAndGroup.Node)
	m.nowNodeLabel2.SetText(nowNodeAndGroup.Node)
}

func (m *mainWindow) subUpdate() {
	message := widgets.NewQMessageBox(m.mainWindow)
	message.SetText("Please Wait, Updating ......")
	message.SetStandardButtons(0)
	message.SetModal(true)

	ctx, cancel := context.WithCancel(context.Background())
	go func(cancelFunc context.CancelFunc) {
		if _, err := apiC.UpdateSub(apiCtx(), &empty.Empty{}); err != nil {
			MessageBox(err.Error())
		}
		cancelFunc()
	}(cancel)

	for {
		select {
		case <-ctx.Done():
			break
		default:
			message.Show()
			// https://socketloop.com/tutorials/golang-qt-progress-dialog-example
			core.QCoreApplication_ProcessEvents(core.QEventLoop__AllEvents)
			continue
		}
		break
	}

	message.SetStandardButtons(widgets.QMessageBox__Ok)
	message.SetText("Updated!")
	m.refresh()
}

func (m *mainWindow) setListener() {
	m.startButton.ConnectClicked(func(bool2 bool) {
		group := m.groupCombobox.CurrentText()
		remarks := m.nodeCombobox.CurrentText()
		_, err := apiC.ChangeNowNode(apiCtx(), &api.NowNodeGroupAndNode{Group: group, Node: remarks})
		if err != nil {
			MessageBox(err.Error())
			return
		}
		m.nowNodeLabel2.SetText(remarks)
	})

	m.groupCombobox.ConnectCurrentTextChanged(func(string2 string) {
		node, err := apiC.GetNode(apiCtx(), &wrappers.StringValue{Value: m.groupCombobox.CurrentText()})
		if err != nil {
			MessageBox(err.Error())
			return
		}
		m.nodeCombobox.Clear()
		m.nodeCombobox.AddItems(node.Value)
	})

	m.latencyButton.ConnectClicked(func(bool2 bool) {
		go func() {
			t := time.Now()
			lat, err := apiC.Latency(apiCtx(), &api.NowNodeGroupAndNode{Group: m.groupCombobox.CurrentText(), Node: m.nodeCombobox.CurrentText()})
			if err != nil {
				m.latencyLabel2.SetText(fmt.Sprintf("<i>[%02d:%02d:%02d]</i>  can't connect", t.Hour(), t.Minute(), t.Second()))
				return
			}
			m.latencyLabel2.SetText(fmt.Sprintf("<i>[%02d:%02d:%02d]</i>  %s", t.Hour(), t.Minute(), t.Second(), lat.Value))
		}()
	})

	flowCtx, cancel := context.WithCancel(context.Background())
	cancel()
	m.mainWindow.ConnectShowEvent(func(event *gui.QShowEvent) {
		go func() {
			select {
			case <-flowCtx.Done():
				flowCtx, cancel = context.WithCancel(context.Background())
			default:
				return
			}
			fmt.Println("Call Kernel to Get Flow Message.")
			client, err := apiC.GetRate(flowCtx, &empty.Empty{})
			if err != nil {
				log.Println(err)
				return
			}
			for {
				if m.mainWindow.IsHidden() {
					fmt.Println("Window is Hidden, Send Done to Kernel.")
					cancel()
					break
				}

				all, err := client.Recv()
				if err == io.EOF {
					log.Println(err)
					break
				}
				if err != nil {
					continue
				}
				m.statusLabel2.SetText(fmt.Sprintf("Download<sub><i>(%s)</i></sub>: %s , Upload<sub><i>(%s)</i></sub>: %s", all.Download, all.DownRate, all.Upload, all.UpRate))
			}
		}()
		m.refresh()
	})
}
