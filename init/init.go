package ssr_init

import(
	"os"
	"os/exec"
    "fmt"
//    "runtime"
    "sync"
//	"path/filepath"
//	"database/sql"

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