package subscription

import (
	"database/sql"
	"fmt"
	"log"
	"strconv"

	"../config"
)

// ChangeNowNode 更换节点(数据库)
func ChangeNowNode(sqlPath string) int {
	ShowAllNodeIDAndRemarks(sqlPath)
	db, err := sql.Open("sqlite3", sqlPath)
	if err != nil {
		fmt.Println(err)
	}
	defer db.Close()

	//判断数据库是否为空
	if err = db.QueryRow("SELECT remarks FROM SSR_info;").Scan(err); err == sql.ErrNoRows {
		log.Println("节点列表为空,请先更新订阅")
		return 0
	}

	//获取服务器条数
	var num int
	query, err := db.Prepare("select count(1) from SSR_info")
	if err != nil {
		return 0
	}
	query.QueryRow().Scan(&num)
	//fmt.Println(num)

	fmt.Print(config.GetFunctionString()["returnMenu"] + ">>> ")
	var selectTemp int
	fmt.Scanln(&selectTemp)
	// if select_temp == 0 {
	switch {
	case selectTemp == 0:
		return 0
	case selectTemp > 0 && selectTemp <= num:
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

		SsrSQLChangeNode(strconv.Itoa(selectTemp), sqlPath)
	default:
		fmt.Println("enter error,please retry.")
		ChangeNowNode(sqlPath)
		return 0
	}
	return selectTemp

}

/*
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
*/
