package main

import (
    "fmt"
    //"encoding/base64"
    //"net/http"
    "io/ioutil"
    "strings"
    //"bufio"
    "os"
    "os/exec"
    "bytes"
    "regexp"
    //"time"
    "runtime"
    "database/sql"
    _ "github.com/mattn/go-sqlite3"
    //"sync"
    //"log"
    //"strconv"

    "./net"
    "./subscription"
    "./init"
    "./node"
)

var ssr_config_path string
type ssr_config struct {
    pid_file,log_file,workers string
    python_path,config_path,ssr_path,acl string
    server,server_port,protocol,method,obfs,password,obfsparam,protoparam,local_port,local_address,remarks string
    connect_verbose_info,deamon,fast_open string
}

func ssr_config_init(config_path string)ssr_config{
    pid_file := " --pid-file "+config_path+"/shadowsocksr.pid"
    log_file := " --log-file "+"/dev/null"
    workers := " --workers "+"1 "
    python_path := "/usr/bin/python3 "
    ssr_config_path = "/home/asutorufa/.config/SSRSub/ssr_config.conf"
    return ssr_config{pid_file,log_file,workers,python_path,"","","","","","","","","","","","","","","","",""}
}


//判断目录是否存在返回布尔类型
func path_exists(path string)bool{
    _,err := os.Stat(path)
    if err!=nil{
        if os.IsExist(err){
            return true
        }else{
            return false
        }
    }else{
        return true
    }
}


//读取配置文件
func read_config_db(config_path,db_path string)ssr_config{
    ssr_config := ssr_config_init(config_path)
    //var log_file,pid_file,fast_open,workers,connect_verbose_info,ssr_path,python_path,config_path,config_url string
    config_temp,err := ioutil.ReadFile(ssr_config_path)
    if err != nil {
        fmt.Println(err)
    }
    lines := strings.Split(string(config_temp),"\n")
    re3,_ := regexp.Compile("#.*$")
    for _,config_temp2 := range lines{
        config_temp2 = re3.ReplaceAllString(config_temp2,"")
        config_temp2 := strings.Split(config_temp2," ")
        if config_temp2[0] == "python_path"{
            ssr_config.python_path = config_temp2[1]+" "
        } else if config_temp2[0] == "ssr_path"{
            ssr_config.ssr_path = config_temp2[1]+" "
        }else if config_temp2[0] == "config_path"{
            ssr_config.config_path = config_temp2[1]
        }else if config_temp2[0] == "connect-verbose-info"{
            ssr_config.connect_verbose_info = "--connect-verbose-info "
        }else if config_temp2[0] == "workers"{
            ssr_config.workers = "--workers "+config_temp2[1]+" "
        }else if config_temp2[0] == "fast-open"{
            ssr_config.fast_open = "--fast-open "
        }else if config_temp2[0] == "pid-file"{
            ssr_config.pid_file = "--pid-file "+config_temp2[1]+" "
        }else if config_temp2[0] == "log-file"{
            ssr_config.log_file = "--log-file "+config_temp2[1]+" "
        }else if config_temp2[0] == "local_address"{
            ssr_config.local_address = "-b "+config_temp2[1]+" "
        }else if config_temp2[0] == "local_port"{
            ssr_config.local_port = "-l "+config_temp2[1]+" "
        }else if config_temp2[0] == "acl"{
            ssr_config.acl = "--acl "+config_temp2[1]+" "
        }else if config_temp2[0] == "deamon"{
            ssr_config.deamon = "-d start"
        }
    }

    db,err := sql.Open("sqlite3",db_path)
    if err!=nil{
        fmt.Println(err)
    }
    defer db.Close()
    var server,server_port,protocol,method,obfs,password,obfsparam,protoparam string
    rows,err := db.Query("SELECT server,server_port,protocol,method,obfs,password,obfsparam,protoparam FROM SSR_present_node")
    for rows.Next(){rows.Scan(&server,&server_port,&protocol,&method,&obfs,&password,&obfsparam,&protoparam)}
    ssr_config.server = "-s "+server+" "
    ssr_config.server_port = "-p " +server_port+" "
    ssr_config.protocol = "-O "+protocol+" "
    ssr_config.method = "-m "+method+" "
    ssr_config.obfs = "-o "+obfs+" "
    ssr_config.password = "-k "+password+" "
    ssr_config.obfsparam = "-g "+obfsparam+" "
    ssr_config.protoparam = "-G "+protoparam+" "
    //fmt.Println(ssr_config)
    return ssr_config
}


func ssr_start_db(config_path,db_path string){
    ssr_config := read_config_db(config_path,db_path)
    cmd_temp := ssr_config.python_path+ssr_config.ssr_path+ssr_config.local_address+ssr_config.
    local_port+ssr_config.log_file+ssr_config.pid_file+ssr_config.fast_open+ssr_config.
    workers+ssr_config.connect_verbose_info+ssr_config.server+ssr_config.
    server_port+ssr_config.protocol+ssr_config.method+ssr_config.
    obfs+ssr_config.password+ssr_config.obfsparam+ssr_config.protoparam+ssr_config.acl+ssr_config.deamon

    fmt.Println(cmd_temp)

    var cmd *exec.Cmd
    if runtime.GOOS == "linux"{
        cmd = exec.Command("/bin/sh", "-c",cmd_temp)
    }
    var out bytes.Buffer
    var stderr bytes.Buffer
    cmd.Stdout = &out
    cmd.Stderr = &stderr
    err := cmd.Run()
    if err != nil {
        fmt.Println(fmt.Sprint(err) + ": " + stderr.String())
        return
    }
    fmt.Println("Result: " + out.String())
    //fmt.Println(ssr_config.python_path,ssr_config.config_path,ssr_config.log_file,ssr_config.pid_file,ssr_config.fast_open,ssr_config.workers,ssr_config.connect_verbose_info,ssr_config.ssr_path,ssr_config.server,ssr_config.server_port,ssr_config.protocol,ssr_config.method,ssr_config.obfs,ssr_config.password,ssr_config.obfsparam,ssr_config.protoparam) 
}

/*
func ssr_stop(){
    cmd_temp := "cat "+strings.Split(read_config_db().pid_file," ")[1]+" | xargs kill"
    var cmd *exec.Cmd
    if runtime.GOOS == "linux"{
        cmd = exec.Command("/bin/sh", "-c",cmd_temp)
    }
    var out bytes.Buffer
    var stderr bytes.Buffer
    cmd.Stdout = &out
    cmd.Stderr = &stderr
    err := cmd.Run()
    if err != nil {
        fmt.Println(fmt.Sprint(err) + ": " + stderr.String())
        return
    }
    fmt.Println("Result: " + out.String())
}
*/

func ssr_stop(config_path string){
    if(path_exists(config_path)){

    }
}


func menu_db(path,db_path string){
    //获取当前配置文件路径和可执行文件路径
    ssr_init.Menu_init(path)
    //获取当前节点
    node.Get_now_node(db_path)

    fmt.Print("1.开启ssr\n2.更换节点\n3.更新所有订阅\n4.添加订阅链接\n5.删除订阅链接\n6.获取延迟\n7.结束ssr后台\n>>>")



    var select_temp string
    fmt.Scanln(&select_temp)

    switch select_temp{
    case "1":
        ssr_start_db(path,db_path)
    case "2":
        node.Ssr_server_node_change(db_path)
    case "3":
        subscription.Delete_config_db(db_path)
        subscription.Add_config_db(db_path)
    case "4":
        fmt.Print("请输入要添加的订阅链接(一条):")
        var link_temp string
        fmt.Scanln(&link_temp)
        subscription.Subscription_link_add(link_temp,db_path)
    case "5":
        subscription.Subscription_link_delete(db_path)
    case "6":
        delay_test_temp := read_config_db(path,db_path)
        socks5.Delay_test(strings.Split(delay_test_temp.local_address," ")[1],strings.Split(delay_test_temp.local_port," ")[1])
    case "7":

    }

}


func main(){
    config_path := os.Getenv("HOME")+"/.config/SSRSub"
    path := os.Getenv("HOME")+"/.config/SSRSub/SSR_config.db"
    menu_db(config_path,path)
}