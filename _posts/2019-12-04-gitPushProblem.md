---
layout:     post
title:      git push输入用户名密码问题
subtitle:   git push的时候老是要输入用户名和密码
date:       2019-12-04
author:     K4ys0n
header-img: img/post-bg-coffee.jpeg
catalog:    true
tags:
    - git
    - windows
    - github
---

## 前言
今天遇到一个git push的问题，就是git push的时候每次都要我输入用户名和密码，很繁琐，因此在网上搜索后尝试了这个办法来解决它。

原因好像是http方式push不会保存密码（虽然我之前也不用输密码，只是突然就开始要了。。），要么密码保存本地，要么改用ssh方式。
## 步骤
#### 1. 方法一，账号密码保存本地
在git push之后，按照提示输入用户名和密码，完成git push操作。然后再输入以下命令：
```sh
git config --global credential.helper store
```
执行上述命令之后会在C:/users/user/目录中产生一个文件.git-credentials，这个文件保存着一个链接，是记录你的账号和密码的。

#### 2. 方法二，改用ssh方式
首先输入以下命令查看git的pull/push方式：
```sh
git remote -v
```
得到如下结果：
```sh
origin  https://github.com/K4ys0n/k4ys0n.github.io.git (fetch)
origin  https://github.com/K4ys0n/k4ys0n.github.io.git (push)
```
接着输入以下命令移除http方式：
```sh
git remote rm origin
git remote -v
```
这时候再查结果已经是空了，然后我们在GitHub仓库中，点击“Clone and download”，点击“Use SSH”，然后复制ssh链接。
 ![ssh1](https://raw.githubusercontent.com/K4ys0n/K4ys0n.github.io/master/img/gitPushProblem-ssh1.jpg)
 ![ssh2](https://raw.githubusercontent.com/K4ys0n/K4ys0n.github.io/master/img/gitPushProblem-ssh2.jpg)
回到命令行，输入以下命令：
```sh
git remote add origin ssh_address   # ssh_address就是用上面获取到的ssh链接
```
然后git remote -v再次查看，就变成如下状态了：
```sh
origin  git@github.com:K4ys0n/k4ys0n.github.io.git (fetch)
origin  git@github.com:K4ys0n/k4ys0n.github.io.git (push)
```
再进行git push，可能会出现如下错误：
```sh
fatal: The current branch master has no upstream branch.
To push the current branch and set the remote as upstream, use

    git push --set-upstream origin master
```
这时再执行以下命令即可：
```sh
git push --set-upstream origin master
```

#### 3. 补充
后来才发现其实是我所在的网络挂了公司的代理，公司的代理是用域名+端口的方式，而我也是用这个方式配置的，才导致git push的时候总是询问密码。

解决方法是，查到代理IP，然后用IP+端口的方式保存在.gitconfig文件中即可，具体操作如下。

先查询代理IP，命令行输入netstat，等候片刻，可以看到如下：
 ![net](https://raw.githubusercontent.com/K4ys0n/K4ys0n.github.io/master/img/gitPushProblem-net.jpg)
在命令行输入以下命令，其中IP地址和端口号替换为上图中的外部地址即可：
```sh
git config --global --unset http.proxy
git config --global http.proxy "10.xx.xx.xx:8081"
```
## 后记
参考：

[解决GitHub每次push时都提示输入用户名和密码的问题](https://blog.csdn.net/mr_javascript/article/details/83043174)
