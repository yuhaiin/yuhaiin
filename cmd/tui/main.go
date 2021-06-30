package main

import (
	"github.com/rivo/tview"
)

func main() {

	application := tview.NewApplication()

	box := tview.NewList().
		AddItem("a", "a", 'a', nil).
		AddItem("b", "b", 'b', nil)

	box2 := tview.NewBox().SetBorder(true).SetTitle("test")
	box3 := tview.NewBox().SetBorder(true).SetTitle("box3")

	// c, err := grpc.DialContext(context.Background(), "127.0.0.1:37231", grpc.WithBlock(), grpc.WithInsecure())
	// if err != nil {
	// 	panic(err)
	// }
	// conn := app.NewConnectionsClient(c)

	// sc, err := conn.Statistic(context.Background(), &emptypb.Empty{})
	// if err != nil {
	// 	panic(err)
	// }
	// go func() {
	// 	ctx := sc.Context()
	// 	for {
	// 		r, err := sc.Recv()
	// 		if err != nil {
	// 			panic(err)
	// 		}
	// 		box3.SetTitle(fmt.Sprintf("down: %s, up: %s", r.DownloadRate, r.UploadRate))
	// 		application.Draw()

	// 		select {
	// 		case <-ctx.Done():
	// 			return
	// 		default:
	// 		}
	// 	}
	// }()

	flex := tview.NewFlex().
		AddItem(box, 20, 1, false).
		AddItem(box3, 0, 1, false).
		AddItem(box2, 20, 1, false)

	if err := application.SetRoot(flex, true).SetFocus(box).Run(); err != nil {
		panic(err)
	}
}
