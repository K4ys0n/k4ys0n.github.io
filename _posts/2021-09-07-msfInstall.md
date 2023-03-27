---
layout:     post            # 使用的布局（不需要改）
title:      MSF 一条命令安装   # 标题
subtitle:   Ubuntu上需要安装MSF，可以使用此命令。  # 副标题
date:       2021-09-07      # 时间
author:     K4ys0n           # 作者
header-img: img/post-bg-coffee.jpeg    # 这篇文章标题背景图片
catalog:    true            # 是否归档
tags:                       # 标签
    - 笔记
    - 网络安全
    - MSF
---


## MSF一条命令安装
```shell
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall
```

PS：但是有时候很慢。