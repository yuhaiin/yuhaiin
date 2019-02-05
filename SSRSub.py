#!/usr/bin/env python3
import base64
import requests
import os
url = "" #订阅链接
list = []
config_path = "~/.cache/SSRSub/config.txt"
SSR_path = "python3 ~/program/shadowsocksr-python/shadowsocks/local.py --connect-verbose-info --workers 8 --fast-open"

def base64d(a):
    return base64.urlsafe_b64decode(a+"="*(len(a)%4))

def update():
    try:
        fo = open(os.path.expanduser(config_path),"w")
    except FileNotFoundError:
        os.makedirs(os.path.expanduser(config_path).replace('/config.txt',''))
        update()
        return;
    fo.write(requests.get(url).text)
    fo.close
    list.clear()
    main()
    return;

def init():
    for line in base64d(open(os.path.expanduser(config_path),"r").read()).split():
        list.append(base64d(line.decode("utf-8").replace('ssr://','')).decode('utf-8').replace('/?obfsparam=',':').replace('&protoparam=',':').replace('&remarks=',':').replace('&group=',':'))
        #print(base64d(line.decode("utf-8").replace('ssr://','')).decode('utf-8').replace('/?obfsparam=',':').replace('&protoparam=',':').replace('&remarks=',':').replace('&group=',':'))
def list_list():
    i=0
    for line in list:
        i=i+1
        temp=line.split(':')
        print(str(i)+':'+base64d(temp[-2]).decode('utf-8'))
    return;

def input_select():
    try:
        global select
        select = input("\n\
enter digital to select server star\n\
enter 'update' to update your config\n\
enter 'exit' to exit\n\
enter 'ping' to start ping test\n\
>>")
        if select=='update':
            update()
            exit()
        elif select=='exit':
            exit()
        elif select=='ping':
            ping_test()
            exit()
    except ValueError:
        print("please enter digital")
        main()
        exit()
    except EOFError:
        exit("")
    except KeyboardInterrupt:
        exit("")

def start():
    temp=list[int(select)-1].split(':')
    if len(temp)==17:
        server=temp[0]+':'+temp[1]+':'+temp[2]+':'+temp[3]+':'+temp[4]+':'+temp[5]+':'+temp[6]+':'+temp[7]
    elif len(temp)==10:
        server=temp[0]

    server_port=temp[-9]
    protocol=temp[-8]
    method=temp[-7]
    obfs=temp[-6]
    password=base64d(temp[-5]).decode('utf-8')
    obfsparam=base64d(temp[-4]).decode('utf-8')
    protoparam=base64d(temp[-3]).decode('utf-8')
    remarks=base64d(temp[-2]).decode('utf-8')
    print(remarks)
    print(server)
    print(server_port)
    print(protocol)
    print(method)
    print(obfs)
    print(password)
    print(obfsparam)
    print(protoparam)

    os.system("%s -l 1080 -s %s -p %s -k %s -m %s -o %s -O %s -G %s -g \
                %s" % (SSR_path,server,server_port,password,method,obfs,\
                protocol,protoparam,obfsparam))


def ping_test():
    try:
        select=input("enter digital to ping test>>")
        temp=list[int(select)-1].split(':')
        if len(temp)==17:
            server=temp[0]+':'+temp[1]+':'+temp[2]+':'+temp[3]+':'+temp[4]+':'+temp[5]+':'+temp[6]+':'+temp[7]
        elif len(temp)==10:
            server=temp[0]

        if select=='exit':
            main()
            exit()

        os.system("ping -c 3 %s" % (server))
        ping_test()
        
    except EOFError:
        main()
        return;
    except KeyboardInterrupt:
        main()
        return;


 

def main():
    list.clear()
    try:
        init()
    except FileNotFoundError:
        print("please update config.")
    list_list()
    input_select()
    try:
        start()
    except ValueError:
        print("please enter number")
        main()

if __name__ == '__main__':
    main()
