package subscription

import (
	"database/sql"
	"fmt"
	"log"
	"strconv"
	"sync"
	// _ "github.com/mattn/go-sqlite3"
	//"time"
)

//打印数据库中的配置文件
func List_list_db(sql_path string) {
	//访问数据库
	db := Get_db(sql_path)
	defer db.Close()

	//查找
	rows, err := db.Query("SELECT id,remarks FROM SSR_info ORDER BY id ASC;")
	if err != nil {
		log.Println(err)
	}
	//var server,server_port,protocol,method,obfs,password,obfsparam,protoparam string
	var remarks, id string
	for rows.Next() {
		//err = rows.Scan(&server,&server_port,&protocol,&method,&obfs,&password,&obfsparam,&protoparam)
		err = rows.Scan(&id, &remarks)
		fmt.Println(id + "." + remarks)
	}
}

//更换节点(数据库)
func Ssr_server_node_change(sql_path string) int {
	List_list_db(sql_path)
	db := Get_db(sql_path)
	defer db.Close()

	//判断数据库是否为空
	var err error
	if err = db.QueryRow("SELECT remarks FROM SSR_info;").Scan(err); err == sql.ErrNoRows {
		log.Println("节点列表为空,请先更新订阅")
		return 0
	}

	//获取服务器条数
	var num int
	query, err := db.Prepare("select count(1) from SSR_info")
	query.QueryRow().Scan(&num)
	//fmt.Println(num)

	fmt.Print("\n输入0返回菜单,输入列表前的数字更换节点>>>")
	var select_temp int
	fmt.Scanln(&select_temp)
	// if select_temp == 0 {
	switch {
	case select_temp == 0:
		return 0
	case select_temp > 0 && select_temp <= num:
		/*旧版更新 个人感觉太罗嗦
		        rows, err := db.Query("SELECT remarks,server,server_port,protocol,method,obfs,password,obfsparam,protoparam FROM SSR_info WHERE id = ?",select_temp)
		        if err!=nil{
		            fmt.Println(err)
		        }
		        var remarks,server,server_port,protocol,method,obfs,password,obfsparam,protoparam string
			    for rows.Next(){rows.Scan(&remarks,&server,&server_port,&protocol,&method,&obfs,&password,&obfsparam,&protoparam)}

		        fmt.Println(remarks,server,server_port,protocol,method,obfs,password,obfsparam,protoparam)
		        //更新表
		        db.Exec("UPDATE SSR_present_node SET remarks = ?,server = ?,server_port = ?,protocol = ?,method = ?,obfs = ?,password = ?,obfsparam = ?,protoparam = ?",remarks,server,server_port,protocol,method,obfs,password,obfsparam,protoparam)
		*/
		//temp := time.Now()

		/*
			db.Exec("BEGIN TRANSACTION;")
			db.Exec("DELETE FROM SSR_present_node")
			db.Exec("INSERT INTO SSR_present_node(remarks,server,server_port,protocol,method,obfs,password,obfsparam,protoparam) SELECT remarks,server,server_port,protocol,method,obfs,password,obfsparam,protoparam FROM SSR_info WHERE id = ?", select_temp)
			db.Exec("COMMIT;")
		*/
		SsrSQLChangeNode(strconv.Itoa(select_temp), sql_path)
	default:
		fmt.Println("enter error,please retry.")
		Ssr_server_node_change(sql_path)
		return 0
	}
	return select_temp

}

// SsrSQLChangeNode change now node
func SsrSQLChangeNode(id, sqlPath string) {
	db := Get_db(sqlPath)
	defer db.Close()
	db.Exec("BEGIN TRANSACTION;")
	db.Exec("DELETE FROM SSR_present_node")
	db.Exec("INSERT INTO SSR_present_node(remarks,server,server_port,protocol,method,obfs,password,obfsparam,protoparam) SELECT remarks,server,server_port,protocol,method,obfs,password,obfsparam,protoparam FROM SSR_info WHERE id = ?", id)
	db.Exec("COMMIT;")
}

func Ssr_server_node_init(sql_path string, wg *sync.WaitGroup) {

	db := Get_db(sql_path)
	//关闭数据库
	defer db.Close()

	//创建表
	db.Exec("BEGIN TRANSACTION;")
	sql_table := `CREATE TABLE IF NOT EXISTS SSR_present_node(
        remarks TEXT,
        server TEXT,
        server_port TEXT,
        protocol TEXT,
        method TEXT,
        obfs TEXT,
        password TEXT,
        obfsparam TEXT,
		protoparam TEXT);`
	db.Exec(sql_table)
	//初始化插入空字符
	//db.Exec("INSERT INTO SSR_present_node(remarks,server,server_port,protocol,method,obfs,password,obfsparam,protoparam)values('none','none','none','none','none','none','none','none','none')")
	db.Exec("COMMIT;")

	wg.Done()
}

func GetNowNode(sql_path string) string {
	db := Get_db(sql_path)
	defer db.Close()
	var remarks string
	if err := db.QueryRow("SELECT remarks FROM SSR_present_node;").Scan(&remarks); err == sql.ErrNoRows {
		log.Println("节点列表为空,请先更新订阅")
		return ""
	}
	/*
			rows, err := db.Query("SELECT remarks FROM SSR_present_node;")
			var remarks string
			for rows.Next() {
				rows.Scan(&remarks)
		    }
	*/
	return remarks
}

func Get_now_node(sql_path string) {
	// db := Get_db(sql_path)
	// defer db.Close()
	// var remarks string
	// if err := db.QueryRow("SELECT remarks FROM SSR_present_node;").Scan(&remarks); err == sql.ErrNoRows {
	// 	log.Println("节点列表为空,请先更新订阅")
	// }
	// /*
	// 		rows, err := db.Query("SELECT remarks FROM SSR_present_node;")
	// 		var remarks string
	// 		for rows.Next() {
	// 			rows.Scan(&remarks)
	// 	    }
	// */
	fmt.Println("当前使用节点:", GetNowNode(sql_path))
}
