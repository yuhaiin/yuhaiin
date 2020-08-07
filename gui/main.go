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
	window          *widgets.QMainWindow
	flow            *widgets.QLabel
	nowNodeLabel    *widgets.QLabel
	nowNode         *widgets.QLabel
	groupLabel      *widgets.QLabel
	groupCombobox   *widgets.QComboBox
	nodeLabel       *widgets.QLabel
	nodeCombobox    *widgets.QComboBox
	startButton     *widgets.QPushButton
	latencyLabel    *widgets.QLabel
	latency         *widgets.QLabel
	latencyButton   *widgets.QPushButton
	subButton       *widgets.QPushButton
	subUpdateButton *widgets.QPushButton
	settingButton   *widgets.QPushButton

	menuBar *widgets.QMenuBar

	flowCtx    context.Context
	flowCancel context.CancelFunc
}

func NewMain() *mainWindow {
	m := &mainWindow{}
	m.window = widgets.NewQMainWindow(nil, core.Qt__Window)
	m.window.SetWindowFlag(core.Qt__WindowSystemMenuHint, true)
	m.window.SetWindowTitle("YUHAIIN")

	m.create()
	m.setLayout()
	m.setListener()

	return m
}

func (m *mainWindow) setMenuBar(menubar *widgets.QMenuBar) {
	m.window.SetMenuBar(menubar)
}

func (m *mainWindow) create() {
	m.flow = widgets.NewQLabel2("", nil, core.Qt__Widget)

	m.nowNodeLabel = widgets.NewQLabel2("Now Use", nil, core.Qt__Widget)
	m.nowNode = widgets.NewQLabel2("", nil, core.Qt__Widget)

	m.groupLabel = widgets.NewQLabel2("Group", nil, core.Qt__Widget)
	m.groupCombobox = widgets.NewQComboBox(nil)

	m.nodeLabel = widgets.NewQLabel2("Node", nil, core.Qt__Widget)
	m.nodeCombobox = widgets.NewQComboBox(nil)

	m.startButton = widgets.NewQPushButton2("Use", nil)
	m.latencyLabel = widgets.NewQLabel2("Latency", nil, core.Qt__Widget)
	m.latency = widgets.NewQLabel2("", nil, core.Qt__Widget)
	m.latencyButton = widgets.NewQPushButton2("Test", nil)
}

func (m *mainWindow) setLayout() {
	windowLayout := widgets.NewQGridLayout2()
	windowLayout.AddWidget3(m.flow, 0, 0, 1, 3, 0)
	windowLayout.AddWidget2(m.nowNodeLabel, 1, 0, 0)
	windowLayout.AddWidget2(m.nowNode, 1, 1, 0)
	windowLayout.AddWidget2(m.groupLabel, 2, 0, 0)
	windowLayout.AddWidget2(m.groupCombobox, 2, 1, 0)
	windowLayout.AddWidget2(m.nodeLabel, 3, 0, 0)
	windowLayout.AddWidget2(m.nodeCombobox, 3, 1, 0)
	windowLayout.AddWidget2(m.startButton, 3, 2, 0)
	windowLayout.AddWidget2(m.latencyLabel, 4, 0, 0)
	windowLayout.AddWidget2(m.latency, 4, 1, 0)
	windowLayout.AddWidget2(m.latencyButton, 4, 2, 0)

	centralWidget := widgets.NewQWidget(m.window, 0)
	centralWidget.SetLayout(windowLayout)
	m.window.SetCentralWidget(centralWidget)
}

func (m *mainWindow) setListener() {
	m.startButton.ConnectClicked(m.startCall)
	m.groupCombobox.ConnectCurrentTextChanged(m.groupChangeCall)
	m.latencyButton.ConnectClicked(m.latencyCall)
	m.window.ConnectShowEvent(m.showCall)
}

func (m *mainWindow) refresh() {
	group, err := apiC.GetGroup(context.Background(), &empty.Empty{})
	if err != nil {
		MessageBox(err.Error())
		return
	}
	m.groupCombobox.Clear()
	m.groupCombobox.AddItems(group.Value)

	//nodeData := map[string][]*core.QVariant{}
	//var nodes []*core.QVariant
	//nodes = append(nodes, core.NewQVariant23(map[string]*core.QVariant{}))
	//nodeData["group"] = nodes
	//for key := range nodeData {
	//	m.groupCombobox.AddItem(key, core.NewQVariant22(nodeData[key]))
	//}

	node, err := apiC.GetNode(context.Background(), &wrappers.StringValue{Value: m.groupCombobox.CurrentText()})
	if err != nil {
		MessageBox(err.Error())
		return
	}
	m.nodeCombobox.Clear()
	m.nodeCombobox.AddItems(node.Value)

	nowNodeAndGroup, err := apiC.GetNowGroupAndName(context.Background(), &empty.Empty{})
	if err != nil {
		MessageBox(err.Error())
		return
	}

	m.groupCombobox.SetCurrentText(nowNodeAndGroup.Group)
	m.nodeCombobox.SetCurrentText(nowNodeAndGroup.Node)
	m.nowNode.SetText(nowNodeAndGroup.Node)
}

func (m *mainWindow) subUpdate() {
	message := widgets.NewQMessageBox(m.window)
	message.SetText("Please Wait, Updating ......")
	message.SetStandardButtons(widgets.QMessageBox__NoButton)
	message.SetModal(true)

	ctx, cancel := context.WithCancel(context.Background())
	go func(cancelFunc context.CancelFunc) {
		if _, err := apiC.UpdateSub(context.Background(), &empty.Empty{}); err != nil {
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

func (m *mainWindow) startCall(_ bool) {
	group := m.groupCombobox.CurrentText()
	remarks := m.nodeCombobox.CurrentText()
	_, err := apiC.ChangeNowNode(context.Background(), &api.NowNodeGroupAndNode{Group: group, Node: remarks})
	if err != nil {
		MessageBox(err.Error())
		return
	}
	m.nowNode.SetText(remarks)
}

func (m *mainWindow) groupChangeCall(str string) {
	node, err := apiC.GetNode(context.Background(), &wrappers.StringValue{Value: str})
	if err != nil {
		MessageBox(err.Error())
		return
	}
	m.nodeCombobox.Clear()
	m.nodeCombobox.AddItems(node.Value)

	//m.nodeCombobox.Clear()
	//nodes := m.nodeCombobox.CurrentData(int(core.Qt__UserRole) + 1).ToList()
	//for _, node := range nodes {
	//	mapTmp := node.ToMap()
	//	for key := range mapTmp {
	//		m.nodeCombobox.AddItem(mapTmp[key].ToString(), core.NewQVariant12(key))
	//	}
	//}
}

func (m *mainWindow) latencyCall(_ bool) {
	go func() {
		t := time.Now()
		lat, err := apiC.Latency(context.Background(), &api.NowNodeGroupAndNode{Group: m.groupCombobox.CurrentText(), Node: m.nodeCombobox.CurrentText()})
		if err != nil {
			m.latency.SetText(fmt.Sprintf("<i>[%02d:%02d:%02d]</i>  timeout: %s", t.Hour(), t.Minute(), t.Second(), m.nodeCombobox.CurrentText()))
			return
		}
		m.latency.SetText(fmt.Sprintf("<i>[%02d:%02d:%02d]</i>  %s", t.Hour(), t.Minute(), t.Second(), lat.Value))
	}()
}

func (m *mainWindow) showCall(_ *gui.QShowEvent) {
	go func() {
		if m.flowCtx == nil {
			m.flowCtx, m.flowCancel = context.WithCancel(context.Background())
			goto _jumpSelect
		}
		select {
		case <-m.flowCtx.Done():
			m.flowCtx, m.flowCancel = context.WithCancel(context.Background())
		default:
			return
		}
	_jumpSelect:
		fmt.Println("Call Kernel to Get Flow Message.")
		client, err := apiC.GetRate(m.flowCtx, &empty.Empty{})
		if err != nil {
			log.Println(err)
			return
		}
		for {
			if m.window.IsHidden() {
				fmt.Println("Window is Hidden, Send Done to Kernel.")
				m.flowCancel()
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
			m.flow.SetText(fmt.Sprintf("Download<sub><i>(%s)</i></sub>: %s , Upload<sub><i>(%s)</i></sub>: %s", all.Download, all.DownRate, all.Upload, all.UpRate))
		}
	}()
	m.refresh()
}
