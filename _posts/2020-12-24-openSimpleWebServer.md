---
layout:     post
title:      如何快速开启一个简单的HTTP服务器
subtitle:    利用php、python2或python3，一条命令开启一个简单本地HTTP服务器。
date:       2020-12-24
author:     K4ys0n
header-img: img/home-bg-geek.jpg
catalog:    true
tags:
    - php
    - python
---



## 注意

注意开服务器不要用太小的端口号，也不要在家目录直接开，找个安全点的目录打开命令行或者终端开启。



## php版

php5.6以上环境下，命令行执行

```
php -S 0.0.0.0:9000
```



## python2版

```
python -m SimpleHTTPServer 9000
```



## python3版

```
python3 -m http.server 9000
```

