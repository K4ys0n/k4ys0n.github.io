---
layout:     post
title:      git安装与配置
subtitle:   windows下安装git，并且配置其提交到GitHub项目
date:       2019-11-20
author:     K4ys0n
header-img: img/post-bg-coffee.jpeg
catalog:    true
tags:
    - git
    - windows
    - github
---

## 前言

在搭建了博客之后，发现用GitHub桌面版来提交代码十分慢，不如直接命令行来得快~所以直接上git。

当然啦，git还有很多功能，这里就不多赘述，先说说怎么安装和配置。

 ![git_logo](https://raw.githubusercontent.com/K4ys0n/K4ys0n.github.io/master/img/gitInstall%26config-logo.jpg)

## 步骤
#### 1. git安装
下载[Git](https://git-scm.com/downloads)对应windows版本，本文下载时git版本是2.24.0，64-bit Git For Windows Setup。

 ![git_downloads](https://raw.githubusercontent.com/K4ys0n/K4ys0n.github.io/master/img/gitInstall%26config-downloads.jpg)

下载完成后双击exe文件

 ![git_exe](https://raw.githubusercontent.com/K4ys0n/K4ys0n.github.io/master/img/gitInstall%26config-exe.jpg)

接着一直next就可以了，中间有一步可以修改安装路径，我这里修改到自己创建的目录去了。如果要桌面图标也可以在下图中第一个空勾选。

 ![git_folder](https://raw.githubusercontent.com/K4ys0n/K4ys0n.github.io/master/img/gitInstall%26config-folder.jpg)

 ![git_dt](https://raw.githubusercontent.com/K4ys0n/K4ys0n.github.io/master/img/gitInstall%26config-dt.jpg)

安装完finish即可。

#### 2. 配置

安装完成可以在开始菜单-所有程序-Git文件夹下看到三个程序：Git Bash，Git CMD，Git GUI。

Bash风格是Linux，CMD就是windows命令行，GUI是界面不推荐使用。在windows下操作Git比较推荐用CMD和BASH，当然也可以直接打开命令行操作git。

打开CMD，输入以下命令，即可查看配置
```sh
git config -l
```
设置用户名和邮箱，不加--global则是配置单个项目，而不是用户级。由于本人所处网络有代理，所以又配置了代理。
```sh
git config --global user.name "K4ys0n"  #名称
git config --global user.email "xxx@xx.xx"  # 邮箱
git config --global http.proxy "xxxxx:8081" # 代理
```
这里git config有三个可选项：
```sh
--local 项目级
--global 当前用户级
--system 系统级
```
以上配置我们都可以在C:/Users/User/.gitconfig看到（不同计算机可能.gitconfig文件存储的路径不一样，搜索一下，一般是在C盘下的某个文件夹中）

 ![git_gc1](https://raw.githubusercontent.com/K4ys0n/K4ys0n.github.io/master/img/gitInstall%26config-gc1.jpg)

 ![git_gc2](https://raw.githubusercontent.com/K4ys0n/K4ys0n.github.io/master/img/gitInstall%26config-gc2.jpg)

删除配置
```sh
git config --global --unset user.name
git config --global --unset user.email
git config --global --unset http.proxy
```

其他配置项
```sh
git config --global color.ui true       # 打开所有的默认终端着色
git config --global alias.ci commit     # 别名 ci 是commit的别名
[alias]  
co = checkout  
ci = commit  
st = status  
pl = pull  
ps = push  
dt = difftool  
l = log --stat  
cp = cherry-pick  
ca = commit -a  
b = branch 

user.name                       # 用户名
user.email                      # 邮箱
core.editor                     # 文本编辑器  
merge.tool                      # 差异分析工具  
core.paper "less -N"            # 配置显示方式  
color.diff true                 # diff颜色配置  
alias.co checkout               # 设置别名
git config user.name            # 获得用户名
git config core.filemode false  # 忽略修改权限的文件
```
如果你在GitHub上已有仓库，那么直接克隆下来；如果没有，可以直接在本地新建完上传上去。
#### 3. 本地新建仓库
打开一个空的文件夹（比如新建一个文件夹workspace），你将在这个文件夹下创建git配置和GitHub工程。

右键打开Git Bash， 输入以下命令初始化git环境和创建工程：
```sh
git init project_name       # project_name就是你要创建的工程名，或者说仓库名
```

#### 4. 克隆远程仓库
首先在浏览器登录你的GitHub账号，找到你的项目仓库，点击“Clone and download”，然后复制链接。
 ![clone](https://raw.githubusercontent.com/K4ys0n/K4ys0n.github.io/master/img/gitInstall&Config-clone.jpg)
打开一个空的文件夹（比如新建一个文件夹workspace），输入“git clone ”加上刚才复制的链接：
```sh
git clone xxxx      # xxxx为刚才复制的链接
```

## 后记
参考：[一个小时学会Git](https://www.cnblogs.com/best/p/7474442.html#_label0)
