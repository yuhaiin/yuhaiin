package subscription

import (
    "fmt"
    "database/sql"
	_ "github.com/mattn/go-sqlite3"
    "strconv"
    "net/http"
    "io/ioutil"
    "strings"
    "bufio"
    "sync"
    "log"
    //"time"
    "../base64d"
)


//读取订阅链接(数据库)
func Get_subscription_link(sql_db_path string)[]string{
    db,err := sql.Open("sqlite3",sql_db_path)
    if err!=nil{
        fmt.Println(err)
    }
    defer db.Close()
    rows,err := db.Query("SELECT link FROM subscription_link;")
    if err != nil{
        fmt.Println(err)
    }

    var subscription_link[] string
    for rows.Next(){
        var link string
        rows.Scan(&link)
        subscription_link = append(subscription_link,link)
    }
    return subscription_link
}

//初始化订阅连接数据库
func Subscription_link_init(sql_db_path string,wg *sync.WaitGroup){
    db,err := sql.Open("sqlite3",sql_db_path)
    if err!=nil{
        fmt.Println(err)
        return
    }
    //关闭数据库
    defer db.Close()
    //创建表
    db.Exec("CREATE TABLE IF NOT EXISTS subscription_link(link TEXT);")

    wg.Done()
}

//添加订阅链接
func Subscription_link_add(subscription_link,sql_db_path string){
    db,err := sql.Open("sqlite3",sql_db_path)
    if err!=nil{
        fmt.Println(err)
        return
    }
    defer db.Close()
    db.Exec("INSERT INTO subscription_link(link)values(?)",subscription_link)
}

//删除订阅链接(数据库)
func Subscription_link_delete(sql_db_path string){
    var subscription_link[] string
    db,err := sql.Open("sqlite3",sql_db_path)
    if err!=nil{
        fmt.Println(err)
        return
    }
    defer db.Close()

    err = db.QueryRow("SELECT link FROM subscription_link").Scan(err)
    if err == sql.ErrNoRows {
        log.Println("没有已经添加的订阅链接\n")
        return
     }
    rows,err := db.Query("SELECT link FROM subscription_link")
    var link string
    for rows.Next(){
        err = rows.Scan(&link)
        subscription_link = append(subscription_link,link)
    }
    //fmt.Println(subscription_link)
    for num,link_temp := range subscription_link{
        fmt.Println(strconv.Itoa(num+1)+"."+link_temp)
    }
    fmt.Print("\n输入0返回菜单>>>")
    var select_delete int
    fmt.Scanln(&select_delete)    
    if select_delete == 0{
        return
    }else if select_delete>=1&&select_delete<=len(subscription_link){
        db.Exec("DELETE FROM subscription_link WHERE link = ?",subscription_link[select_delete-1])
    }else{
        fmt.Println("enter error,please retry.")
        Subscription_link_delete(sql_db_path)
        return
    }
}


func http_get_subscription(url string)string{
    res,err := http.Get(url)
    if err!=nil{
        fmt.Println(err)
        fmt.Println("如果没有添加订阅链接 建议先添加订阅链接")
    }
    body,err := ioutil.ReadAll(res.Body)
    if err!=nil{
        fmt.Println(err)
        fmt.Println("可能出错原因,请检查能否成功访问订阅连接.")
    }
    return string(body)
    //ioutil.WriteFile(read_config().config_path,[]byte(body),0644)
}

//方便进行分割对字符串进行替换
func str_replace(str string)[]string{
    var config[] string
    scanner := bufio.NewScanner(strings.NewReader(strings.Replace(base64d.Base64d(str),"ssr://","",-1)))
    for scanner.Scan() {
    str_temp := strings.Replace(base64d.Base64d(scanner.Text()),"/?obfsparam=",":",-1)
    str_temp = strings.Replace(str_temp,"&protoparam=",":",-1)
    str_temp = strings.Replace(str_temp,"&remarks=",":",-1)
    str_temp = strings.Replace(str_temp,"&group=",":",-1)
    config = append(config,str_temp)
    }
    return config
}


func str_bas64d(str []string,db *sql.DB){
    for i:= 0;i<len(str);i++{
        config_split := strings.Split(str[i],":")
        var server string
        if len(config_split) == 17 {
            server = config_split[0]+":"+config_split[1]+":"+config_split[2]+":"+config_split[3]+":"+config_split[4]+":"+config_split[5]+":"+config_split[6]+":"+config_split[7]
        } else if len(config_split) == 10 {
            server = config_split[0]
        }
        server_port := config_split[len(config_split)-9]
        protocol := config_split[len(config_split)-8]
        method := config_split[len(config_split)-7]
        obfs := config_split[len(config_split)-6]
        password := base64d.Base64d(config_split[len(config_split)-5])
        obfsparam := base64d.Base64d(config_split[len(config_split)-4])
        protoparam := base64d.Base64d(config_split[len(config_split)-3])
        remarks := base64d.Base64d(config_split[len(config_split)-2])
        //fmt.Println(num,remarks,server,server_port,protocol,method,obfs,password,obfsparam,protoparam)



        //向表中插入数据
        db.Exec("INSERT INTO SSR_info(id,remarks,server,server_port,protocol,method,obfs,password,obfsparam,protoparam)values(?,?,?,?,?,?,?,?,?,?)",i+1,remarks,server,server_port,protocol,method,obfs,password,obfsparam,protoparam)
    }

}
//添加所有订阅的所有节点(sqlite数据库)
func Add_config_db(sql_db_path string){

    //访问数据库
    db,err := sql.Open("sqlite3",sql_db_path)
    if err!=nil{
        fmt.Println(err)
        return
    }

    defer db.Close()

    var str_2 []string
    for _,subscription_link_temp := range Get_subscription_link(sql_db_path){
        str_2 = append(str_2,str_replace(http_get_subscription(subscription_link_temp))...)
    }

    //temp := time.Now()

    db.Exec("BEGIN TRANSACTION;")
    str_bas64d(str_2,db)
    db.Exec("COMMIT;")

    //deply := time.Since(temp)
    //fmt.Println(deply)
}


//删除所有的节点
func Delete_config_db(sql_db_path string){
    //访问数据库
    db,err := sql.Open("sqlite3",sql_db_path)
    if err!=nil{
        fmt.Println(err)
        return
    }

    defer db.Close()

    //清空表
    db.Exec("DELETE FROM SSR_info;")
}

//初始化节点列表
func Init_config_db(sql_db_path string,wg *sync.WaitGroup){

    //访问数据库
    db,err := sql.Open("sqlite3",sql_db_path)
    if err!=nil{
        fmt.Println(err)
        return
    }
    defer db.Close()

    db.Exec("BEGIN TRANSACTION;")
    //创建表
     sql_table := `
    CREATE TABLE IF NOT EXISTS SSR_info(
        id INTERGER,
        remarks TEXT,
        server TEXT,
        server_port TEXT,
        protocol TEXT,
        method TEXT,
        obfs TEXT,
        password TEXT,
        obfsparam TEXT,
        protoparam TEXT
    );
    `
    db.Exec(sql_table)

    //向表中插入none值
    //db.Exec("INSERT INTO SSR_info(id,remarks,server,server_port,protocol,method,obfs,password,obfsparam,protoparam)values(none,none,none,none,none,none,none,none,none,none)")

    db.Exec("COMMIT;")
    wg.Done()
}
