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
    //"regexp"
    //"time"
    "runtime"
    "syscall"
    //"database/sql"
    "log"
    _ "github.com/mattn/go-sqlite3"
    //"sync"
    "strconv"

    "./net"
    "./subscription"
    "./init"
    "./config"
)


func ssr_start_db(config_path,db_path string){
    ssr_config := config.Read_config(config_path,db_path)
    
    cmd_temp := ssr_config.Argument["Python_path"]+ssr_config.Argument["Ssr_path"]+ssr_config.
    Argument["Local_address"]+ssr_config.Argument["Local_port"]+ssr_config.
    Argument["Log_file"]+ssr_config.Argument["Pid_file"]+ssr_config.Argument["Fast_open"]+ssr_config.
    Argument["Workers"]+ssr_config.Argument["Connect_verbose_info"]+ssr_config.
    Node["Server"]+ssr_config.Node["Server_port"]+ssr_config.Node["Protocol"]+ssr_config.
    Node["Method"]+ssr_config.Node["Obfs"]+ssr_config.Node["Password"]+ssr_config.
    Node["Obfsparam"]+ssr_config.Node["Protoparam"]+ssr_config.
    Argument["Acl"]+ssr_config.Argument["Deamon"]

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


func ssr_stop(path string){
    pid,exist := process_get(path)
    if  exist == true {
        cmd_temp := "kill "+pid
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
    } else {
        log.Println("\n")
        log.Printf("cant find the process: %s",pid)
        log.Println("please start ssr first.\n")
        return
    }
}


func process_get(path string)(pid string,isexist bool){
    config_temp := config.Read_config_file(path)
    pid_temp,err := ioutil.ReadFile(strings.Split(config_temp["Pid_file"]," ")[1])
    if err != nil{
        log.Println(err)
        log.Println("cant fild the file,please run ssr start.")
        return
    }
    pid = string(pid_temp)
    pid_int,_ :=strconv.Atoi(pid)
    if  err := syscall.Kill(pid_int, 0); err == nil {
        return pid,true
    } else {
        return "",false
    }
}


func menu_db(path,db_path string){
    //初始化
    ssr_init.Init(path,db_path)
    //获取当前配置文件路径和可执行文件路径
    ssr_init.Menu_init(path)
    //获取当前节点
    subscription.Get_now_node(db_path)
    for{
        fmt.Print("1.开启ssr\n2.更换节点/查看所有节点\n3.更新所有订阅\n4.添加订阅链接\n5.删除订阅链接\n6.获取延迟\n7.结束ssr后台\n8.结束此程序(ssr后台运行)\n>>>")

        var select_temp string
        fmt.Scanln(&select_temp)

        switch select_temp{
            case "1":
                ssr_start_db(path,db_path)
            case "2":
                _,exist := process_get(path)
                if exist == true {
                    ssr_stop(path)
                    subscription.Ssr_server_node_change(db_path)
                    ssr_start_db(path,db_path)
                    } else {
                        subscription.Ssr_server_node_change(db_path)
                    }
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
                delay_test_temp := config.Read_config_file(path)
             /*
                if err!=nil{
                log.Println("读取配置文件出错")
                log.Println(err)
                menu_db(path,db_path)
                break
                }
            */
                socks5.Delay_test(strings.Split(delay_test_temp["Local_address"]," ")[1],strings.Split(delay_test_temp["Local_port"]," ")[1])
            case "7":
                ssr_stop(path)
            case "8":
                os.Exit(0)
            default:
                fmt.Println("输入错误\n")
        }
    }
}


func main(){
    config_path := os.Getenv("HOME")+"/.config/SSRSub"
    path := os.Getenv("HOME")+"/.config/SSRSub/SSR_config.db"
    menu_db(config_path,path)
}