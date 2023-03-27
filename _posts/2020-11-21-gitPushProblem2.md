---
layout:     post
title:      git push弹窗输入密码提示登录失败
subtitle:    git push弹窗输入密码提示Logon failed登录失败问题，用新版git可解决。
date:       2020-11-21
author:     K4ys0n
header-img: img/home-bg-geek.jpg
catalog:    true
tags:
    - git
    - windows
    - github
---


## 问题
最近在git push的时候，老是弹窗提示输入账户密码登录，输入之后又报错
```bash
$ git push
Logon failed, use ctrl+c to cancel basic credential prompt.
Everything up-to-date
```
可以看出登录出错，但实际上执行成功了。

不过还是想彻底解决这个问题。

## 解决方法
百度了一下，应该是新版的git不支持弹出框验证账户密码的方式，所以推送请求被拒绝了。

也就是重新安装新的GIT，根据引导设置即可。

## 版本信息
我使用的旧版本GIT是：Git-2.24.0.2-64-bit

当前最新版本是：Git-2.29.2.2-64-bit

## 步骤
#### 1、进入控制面板卸载旧版本GIT
控制面板 -> 卸载程序 -> 找到git -> 右键卸载 -> 确定即可

#### 2、下载最新版本的GIT
[https://gitforwindows.org/](https://gitforwindows.org/)

#### 3、安装GIT
一路下一步就可以了，如果想安装别的目录，注意在点击下一步的时候留意修改安装路径的选项。

最后关闭的时候注意不需要重启计算机。

#### 4、找个项目文件夹打开git bash
找个本地github项目目录（即目录下有.git文件夹等以前git时的相关文件），右键当前路径打开Git Bash Here。

输入git push
成功！
此时就不会再弹窗登录了。