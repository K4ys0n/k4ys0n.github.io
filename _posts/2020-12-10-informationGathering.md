---
layout:     post
title:      Web笔记（十五）信息搜集
subtitle:   这个系列是整理学习安全的笔记，包括Web和PWN的一些知识。本章是记录信息搜集的常见思路和搜索细节。
date:       2020-12-10
author:     K4ys0n
header-img: img/post-bg-rwd.jpg
catalog:    true
tags:
    - CTF
    - web
    - 网络安全
    - 学习笔记
    - 信息搜集
    - 渗透测试
---



## 0x00 信息搜集种类

- 域名信息
- 敏感日志
- 端口扫描
- 旁站C段
- 整站分析
- Google Hacking
- URL采集
- 信息分析



## 0x01 域名信息

#### 1. 对应ip收集

- 相关域名对应ip，相关工具：nslookup、一些工具网站

#### 2. 子域名收集

- 工具：layer子域名挖掘机、subDomainsBrute

#### 3. whois（注册人）信息查询

- 根据已知域名反查，分析出此域名的注册人、邮箱、电话等
- 工具：爱站网、站长工具、微步在线（[https://x.threatbook.cn](https://x.threatbook.cn)）
- [site.ip138.com](https://site.ip138.com)、[searchdns.netcraft.com](https://searchdns.netcraft.com/)



## 0x02 敏感目录

#### 1. 收集方向

- robots.txt
- 后台目录
- 安装包
- 上传目录
- mysql管理接口
- 安装页面
- phpinfo
- 编辑器
- iis短文件

#### 2. 常用工具

- 字典爆破：御剑、dirbuster、dirsearch、wwwscan、IIS_shortname_Scanner等
- 爬虫：爬行菜刀、webrobot、burpSuite、awvs等

#### 0x03 端口扫描

21    FTP
22    SSH
23    Telnet
110    POP3
1433    Sqlserver
3306    Mysql
3389    Mstsc
8080    Tomcat/jboss
9090    WebSphere
...

常用工具：nmap、portscan、ntscan、telnet



## 0x04 旁站C段

#### 1. 旁站：

同服务器其他站点。

#### 2. C段

同一网段其他服务器。

#### 3.常用工具

- web：k8旁站、御剑1.5
- 端口：portscan



## 0x05 整站分析

#### 1. 操作系统
windows、Linux（大小写都可以则为windows，否则为linux）

#### 2. 脚本格式
asp、aspx、php、jsp

#### 3. 数据库类型
access、sqlserver、mysql、oracle、db2、postgresql、sqlite

#### 4. 防护情况
waf

#### 5. CMS类型
dedecms、diguo、meterinfo、dz等

#### 6. 网站容器
iis、Apache、nginx、tomcat等（抓包或者访问一个不存在的网页报404）



## 0x06 Google Hacking

#### 1. intext:
查找网页中含有xx关键字的网站    例：intext:管理员登录

#### 2. intitle:
查找某个标题    例：intitle:后台登录

#### 3. filetype:
查找某个文件类型的文件    例：数据挖掘 filetype: doc

#### 4. inurl:
查找url中带有某字段的网站    例：inurl:php?id=

#### 5. site:
在某域名中查找信息    例：insite:baidu.com



## 0x07 URL采集

#### 1. 采集相关url的同类网站

如：

- php?id=
- 漏洞网站
- 相同某种指纹网站

#### 2. 常用工具

- 谷歌hacker
- url采集器



## 0x08 后台查找

#### 1. 弱口令默认后台

- admin
- admin/login.asp
- manage
- login.asp

等等常见后台

#### 2. 查看网页的链接

一般来说，网站的主页有管理登录类似的东西，有些可能被管理员删掉

#### 3. 查看网站图片的属性

有些图片链接是从后台获取

#### 4. 查看网站使用的管理系统

查看网站使用的管理系统，从而确定后台（[www.yunsee.cn](https://www.yunsee.cn/)云悉指纹识别；或者网站下的readme.txt、使用说明文件等等）

#### 5. 用工具查找

- wwwscan

- intellitamper
- 御剑

#### 6. robots.txt的帮助

robots.txt文件告诉蜘蛛程序在服务器上什么样的文件可以被查看

#### 7. Google Hacking

#### 8. 查看网站使用的编辑器是否有默认后台

编辑器如：

- eweditor

- fckeditor

#### 9. 短文件利用

如：

```
a~!.asp来代替adminxxxx.asp
```

#### 10. 利用sqlmap读取后台文件

```
sqlmap --sql-shell load_file('d:/wwwroot/index.php');
```



## 0x09 CDN绕过

#### 1. 如何判断网站有没有使用CDN

超级ping，爱站网或站长之家ping检测

- 查找二级域名

- 让服务器主动给你发包（邮件）

- 敏感文件泄露

- 查询历史解析ip（ip138）

- app抓包

#### 2. 访问绕过cdn

- 修改hosts文件