package node


import(
	"fmt"
    "database/sql"
    "sync"
	_ "github.com/mattn/go-sqlite3"
)


//打印数据库中的配置文件
func List_list_db(sql_db_path string){
    //访问数据库
    db,err := sql.Open("sqlite3",sql_db_path)
    if err!=nil{
        fmt.Println(err)
        return
    }
    defer db.Close()

    //查找
	rows, err := db.Query("SELECT id,remarks FROM SSR_info")
    //var server,server_port,protocol,method,obfs,password,obfsparam,protoparam string
    var remarks,id string
	for rows.Next(){
		//err = rows.Scan(&server,&server_port,&protocol,&method,&obfs,&password,&obfsparam,&protoparam)
        err = rows.Scan(&id,&remarks)
        fmt.Println(id+"."+remarks)
	}
}


//更换节点(数据库)
func Ssr_server_node_change(sql_db_path string){
    List_list_db(sql_db_path)
    db,err := sql.Open("sqlite3",sql_db_path)
    if err!=nil{
        fmt.Println(err)
        return
    }
    defer db.Close()

    
    //获取服务器条数
    var num int
    query,err := db.Prepare("select count(1) from SSR_info")
    query.QueryRow().Scan(&num)
    //fmt.Println(num)
    

	var select_temp int
	fmt.Scanln(&select_temp)

    if select_temp>0&&select_temp<=num{
        
        rows, err := db.Query("SELECT remarks,server,server_port,protocol,method,obfs,password,obfsparam,protoparam FROM SSR_info WHERE id = ?",select_temp)
        if err!=nil{
            fmt.Println(err)
        }
        var remarks,server,server_port,protocol,method,obfs,password,obfsparam,protoparam string
	    for rows.Next(){rows.Scan(&remarks,&server,&server_port,&protocol,&method,&obfs,&password,&obfsparam,&protoparam)}

        fmt.Println(remarks,server,server_port,protocol,method,obfs,password,obfsparam,protoparam)
        //更新表
        db.Exec("UPDATE SSR_present_node SET remarks = ?,server = ?,server_port = ?,protocol = ?,method = ?,obfs = ?,password = ?,obfsparam = ?,protoparam = ?",remarks,server,server_port,protocol,method,obfs,password,obfsparam,protoparam)
        
        //db.Exec("UPDATE SSR_present_node SET remarks = SSR_info.remarks,server = SSR_info.server,server_port = SSR_info.server_port,protocol = SSR_info.protocol,method = SSR_info.method,obfs = SSR_info.obfs,password = SSR_info.password,obfsparam = SSR_info.obfsparam,protoparam = SSR_info.protoparam FROM SSR_info WHERE SSR_info.id = ?",select_temp)
        //db.Exec("INSERT OR REPLACE INTO SSR_present_node(remarks,server,server_port,protocol,method,obfs,password,obfsparam,protoparam) SELECT SSR_info.server,server_port = SSR_info.server_port,protocol = SSR_info.protocol,method = SSR_info.method,obfs = SSR_info.obfs,password = SSR_info.password,obfsparam = SSR_info.obfsparam,protoparam = SSR_info.protoparam FROM SSR_info, SSR_present_node WHERE SSR_info.id = ?;",select_temp)
    }else{
        fmt.Println("enter error,please retry.")
        Ssr_server_node_change(sql_db_path)
        return
    }

}

func Ssr_server_node_init(sql_db_path string,wg *sync.WaitGroup){

    db,err := sql.Open("sqlite3",sql_db_path)
    if err!=nil{
        fmt.Println(err)
        return
    }
    //关闭数据库
    defer db.Close()
	//创建表
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
	db.Exec("INSERT INTO SSR_present_node(remarks,server,server_port,protocol,method,obfs,password,obfsparam,protoparam)values('none','none','none','none','none','none','none','none','none')")


    wg.Done()
}

func Get_now_node(sql_db_path string){
    db,err := sql.Open("sqlite3",sql_db_path)
    if err!=nil{
        fmt.Println(err)
        return
    }
    defer db.Close()
    rows,err := db.Query("SELECT remarks FROM SSR_present_node;")
    var remarks string
    for rows.Next(){rows.Scan(&remarks)}
    fmt.Println("当前使用节点:",remarks)
}