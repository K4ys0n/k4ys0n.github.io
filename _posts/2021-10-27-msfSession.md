---
layout:     post            # 使用的布局（不需要改）
title:      MSF 后台监听   # 标题
subtitle:   MSF上后台监听需要注意防止session断连假连接。  # 副标题
date:       2021-10-27      # 时间
author:     K4ys0n           # 作者
header-img: img/post-bg-coffee.jpeg    # 这篇文章标题背景图片
catalog:    true            # 是否归档
tags:                       # 标签
    - 笔记
    - 网络安全
    - MSF
---

## 笔记
MSF
1. 防止假session
在实战中，经常会遇到假session或者刚连接就断开的情况，这里补充一些监听参数，防止假死与假session。
```shell
msf exploit(multi/handler) > set ExitOnSession false //可以在接收到seesion后继续监听端口，保持侦听
```

2. 防止session意外退出
```shell
msf6 exploit(multi/handler) > set SessionCommunicationTimeout 0     //默认情况下，如果一个会话将在5分钟（300秒）没有任何活动，那么它会被杀死,为防止此情况可将此项修改为0
msf6 exploit(multi/handler) > set SessionExpirationTimeout 0 //默认情况下，一个星期（604800秒）后，会话将被强制关闭,修改为0可永久不会被关闭
```


3. handler后台持续监听
```shell
msf exploit(multi/handler) > exploit -j -z
```
