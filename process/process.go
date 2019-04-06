package ssr_process

import (
	"fmt"
    "os/exec"
    "runtime"
    "syscall"
    "strconv"
    "strings"
    "bytes"
    "log"
    "io/ioutil"
    "../config"
    // _ "github.com/mattn/go-sqlite3"
)

func Start(config_path,db_path string){
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


func Stop(path string){
    pid,exist := Get(path)
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


func Get(path string)(pid string,isexist bool){
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