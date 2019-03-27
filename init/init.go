package ssr_init

import(
	"os"
	"os/exec"
    "fmt"
    //"runtime"
    "sync"
	//"path/filepath"
	//"database/sql"
    "io/ioutil"

	"../subscription"
	"../node"
    "path/filepath"
)


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

func Init(config_path,sql_db_path string){
    //判断目录是否存在 不存在则创建
    if !path_exists(config_path){
        err := os.MkdirAll(config_path, os.ModePerm)
        if err!=nil{
            fmt.Println(err)
        }
	}
	
	if !path_exists(sql_db_path){
        var wg sync.WaitGroup

        wg.Add(1)
        go subscription.Subscription_link_init(sql_db_path,&wg)
        wg.Add(1)
        go subscription.Init_config_db(sql_db_path,&wg)
        wg.Add(1)
        go node.Ssr_server_node_init(sql_db_path,&wg)
        Auto_create_config(config_path)


        wg.Wait()


    }
}

func Menu_init(path string){
        //获取当前可执行文件目录
        file, _ := exec.LookPath(os.Args[0])
        path2, _ := filepath.Abs(file)
        //fmt.Println(path2)
        rst := filepath.Dir(path2)
        //fmt.Println(rst)
    
        //判断目录是否存在 不存在则创建
        if !path_exists(path){
            err := os.Mkdir(path, os.ModePerm)
            if err!=nil{
                fmt.Println(err)
            }
        }
    
        fmt.Println("当前配置文件目录:"+path)
        fmt.Println("当前可执行文件目录:"+rst)
}

func Auto_create_config(path string){
    config_path := path + "/ssr_config.conf"
    ssr_path := "ssr_path /home/asutorufa/program/shadowsocksr-python/shadowsocks/local.py #ssr路径\n"
    pid_file := "pid-file "+os.Getenv("HOME")+"/.config/SSRSub/shadowsocksr.pid\n"
    log_file := "log-file /dev/null\n"
    fast_open := "fast-open\n"
    deamon := "deamon\n"
    workers := "workers 8\n"
    local_address := "local_address 127.0.0.1\n"
    local_port := "local_port 1080\n"
    connect_verbose_info := "#connect-verbose-info\n"
    acl := "#acl " + os.Getenv("HOME")+"/.config/SSRSub/aacl-none.acl"
    python_path := "python_path /usr/bin/python3 #python路径\n"
    config_conf := python_path + ssr_path + pid_file + log_file + fast_open + deamon + workers + local_address + local_port  + connect_verbose_info + acl
    fmt.Println(config_conf)
    ioutil.WriteFile(config_path,[]byte(config_conf),0644)
}