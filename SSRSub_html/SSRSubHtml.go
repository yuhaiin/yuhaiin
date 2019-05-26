package main

import (
	"os"

	getdelay "../net"
	ssr_process "../process"
	"../subscription"

	"github.com/apcera/termtables"
	"github.com/gin-gonic/gin"
	_ "github.com/mattn/go-sqlite3"
)

var configPath = os.Getenv("HOME") + "/.config/SSRSub"
var sqlPath = configPath + "/SSR_config.db"

func main() {
	// box := packr.New("html", "./html")
	router := gin.Default()

	// file, _ := exec.LookPath(os.Args[0])
	// path2, _ := filepath.Abs(file)
	// rst := filepath.Dir(path2)
	router.LoadHTMLGlob("./**/**")

	// router.Use(gin.WrapH(http.StripPrefix("/", http.FileServer(box))))

	router.GET("/", func(c *gin.Context) {
		_, ssrStatus := ssr_process.Get(configPath)
		c.HTML(200, "sidebar.html", gin.H{
			"now_node":       subscription.GetNowNode(sqlPath),
			"ssr_status":     ssrStatus,
			"title":          "SSRSub",
			"server_remarks": subscription.GetAllNodeRemarksAndID(sqlPath),
			"home":           true,
		})
	})

	router.POST("/submit", func(c *gin.Context) {
		id, _ := c.GetPostForm("server")
		subscription.SsrSQLChangeNode(id, sqlPath)
		_, ssrStatus := ssr_process.Get(configPath)
		if ssrStatus == true {
			ssr_process.Stop(configPath)
			ssr_process.Start(configPath, sqlPath)
		}
		node := subscription.GetOneNodeAll(id, sqlPath)
		delay, _ := getdelay.Tcp_delay(node["server"], node["server_port"])
		c.HTML(200, "sidebar.html", gin.H{
			"id":          node["id"],
			"remarks":     node["remarks"],
			"server":      node["server"],
			"server_port": node["server_port"],
			"protocol":    node["protocol"],
			"method":      node["method"],
			"obfs":        node["obfs"],
			"password":    node["password"],
			"obfsparam":   node["obfsparam"],
			"protoparam":  node["protoparam"],
			"delay":       delay,
			"server_bool": true,
		})
	})

	router.GET("/link", func(c *gin.Context) {
		link := subscription.Get_subscription_link(sqlPath)
		linkTable := termtables.CreateTable()
		linkTable.AddTitle("subscription link")
		for num, i := range link {
			// linkHTMLElement := `<input class="checkbox" type="checkbox" value="` + i + `" />`
			linkTable.AddRow(num, i)

		}
		c.HTML(200, "sidebar.html", gin.H{
			"subscription": true,
			"link":         linkTable.Render(),
		})
	})

	router.GET("/information", func(c *gin.Context) {
		id := c.Query("id")
		node := subscription.GetOneNodeAll(id, sqlPath)
		delay, _ := getdelay.Tcp_delay(node["server"], node["server_port"])
		infTable := termtables.CreateTable()
		infTable.AddTitle("Node Information")
		infTable.AddRow("id", node["id"])
		infTable.AddRow("remarks", node["remarks"])
		infTable.AddRow("server", node["server"])
		infTable.AddRow("server_port", node["server_port"])
		infTable.AddRow("protocol", node["protocol"])
		infTable.AddRow("method", node["method"])
		infTable.AddRow("obfs", node["obfs"])
		infTable.AddRow("password", node["password"])
		infTable.AddRow("obfsparam", node["obfsparam"])
		infTable.AddRow("protoparam", node["protoparam"])
		infTable.AddRow("delay", delay)
		// fmt.Println("\n" + infTable.Render())
		c.String(200, infTable.Render())
		// c.JSON(200, gin.H{
		// 	"id":          node["id"],
		// 	"remarks":     node["remarks"],
		// 	"server":      node["server"],
		// 	"server_port": node["server_port"],
		// 	"protocol":    node["protocol"],
		// 	"method":      node["method"],
		// 	"obfs":        node["obfs"],
		// 	"password":    node["password"],
		// 	"obfsparam":   node["obfsparam"],
		// 	"protoparam":  node["protoparam"],
		// 	"delay":       delay / time.Millisecond,
		// })
	})

	router.Run(":8081")

}
