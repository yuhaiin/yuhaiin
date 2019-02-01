#!/usr/bin/env python3
import base64
import requests
import datetime
import os
url = "" #订阅链接
list = []
config_path = "~/.cache/SSRSub/config.txt"
SSR_path = "python3 ~/program/shadowsocksr-python/shadowsocks/local.py"

def base64d(a):
    a=a.replace('_','/').replace('-','+')
    if len(a)%4==0 :
        return base64.b64decode(a)
    elif len(a)%4==1:
        return base64.b64decode(a+"=")
    elif len(a)%4==2:
        return base64.b64decode(a+"==")
    elif len(a)%4==3:
        return base64.b64decode(a+"===")

def update():
    try:
        fo = open(os.path.expanduser(config_path）,"w")
    except FileNotFoundError:
        os.makedirs(os.path.expanduser(config_path）.replace('/config.txt',''))
        update()
        return;
    fo.write(requests.get(url).text)
    fo.close
    list.clear()
    main()
    return;


print(datetime.datetime.now())

def init():
    for line in base64d(open(os.path.expanduser(config_path）,"r").read()).split():
        list.append(base64d(line.decode("utf-8").replace('ssr://','')).decode('utf-8').replace('/?obfsparam=',':').replace('&protoparam=',':').replace('&remarks=',':').replace('&group=',':'))
        #print(base64d(line.decode("utf-8").replace('ssr://','')).decode('utf-8').replace('/?obfsparam=',':').replace('&protoparam=',':').replace('&remarks=',':').replace('&group=',':'))
def list_list():
    i=0
    for line in list:
        i=i+1
        temp=line.split(':')
        print(str(i)+':'+base64d(temp[-2]).decode('utf-8'))
    return;

print(datetime.datetime.now())

def input_select():
    global select
    select = input()
    if int(select)==8888:
        update()
        exit()

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


def main():
    try:
        init()
    except FileNotFoundError:
        print("please update config.")
    list_list()
    try:
        input_select()
    except ValueError:
        print("please enter number")
        list.clear()
        main()
        return;
    start()

if __name__ == '__main__':
    main()
