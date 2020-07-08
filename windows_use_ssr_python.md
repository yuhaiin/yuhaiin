if your method use salsa20 or chacha20,you need to https://download.libsodium.org/libsodium/releases/ download a name like libsodium-\*-msvc.zip,unzip the dll of the Dynamic to C:\Windows\SysWOW64  
My download zip:  
```
- Win32
  - Debug
  - Release
    - v100
    - v110
    - v120
    - v140
    - v141
    - v142
      - dynamic
        - libsodium.dll  <---coopy this file to C:\Windows\SysWOW64
        - libsodium.exp
        - libsodium.lib
        - libsodium.pdb
- include
- X64
```


加密方式若使用:salsa20 or chacha20  
需要到 https://download.libsodium.org/libsodium/releases/ 下载名字为libsodium-\*-msvc(\*为版本号,随便下一个都可以)的zip  
将其中的Win32或Win64的Release中的v*其中的一个的Dynamic中的dll文件解压到C:\Windows\SysWOW64  
我的zip目录类似为:

```
- Win32
  - Debug
  - Release
    - v100
    - v110
    - v120
    - v140
    - v141
    - v142
      - dynamic
        - libsodium.dll  <---这个文件
        - libsodium.exp
        - libsodium.lib
        - libsodium.pdb
- include
- X64
```