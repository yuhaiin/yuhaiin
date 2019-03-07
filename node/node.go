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
    db,err := sql.Open("sqlit3",sql_db_path)
    if err!=nil{
        fmt.Println(err)
        return
    }

    //获取服务器条数
    var num int
    query,err := db.Prepare("select count(1) from SSR_info") 
    query.QueryRow().Scan(&num)
    fmt.Println(num)

	var select_temp int
	fmt.Scanln(&select_temp)

    if select_temp>0&&select_temp<=num{
        rows, err := db.Query("SELECT remarks,server,server_port,protocol,method,obfs,password,obfsparam,protoparam FROM SSR_info WHERE id = ?",select_temp)
        if err!=nil{
            fmt.Println(err)
            return
        }
        var remarks,server,server_port,protocol,method,obfs,password,obfsparam,protoparam string
	    for rows.Next(){rows.Scan(&remarks,&server,&server_port,&protocol,&method,&obfs,&password,&obfsparam,&protoparam)}

        //更新表
        db.Exec("UPDATE SSR_present_node SET remarks=?,server=?,server_port=?,protocol=?,method=?,obfs=?,password=?,obfsparam=?,protoparam=?",remarks,server,server_port,protocol,method,obfs,password,obfsparam,protoparam)
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