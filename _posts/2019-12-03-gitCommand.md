---
layout:     post
title:      git基础知识和常用命令
subtitle:   简单介绍一下git的架构和组成，列举常用命令。
date:       2019-12-03
author:     K4ys0n
header-img: img/post-bg-coffee.jpeg
catalog:    true
tags:
    - git
    - github
---

## 前言
我用git和GitHub来做版本控制和代码仓库管理，这里就简单介绍一下git的基础知识，了解一下git架构和组成，最后再稍微记录一下常用的git命令吧！
#### 1. git命令原理和文件状态

 ![framework](https://raw.githubusercontent.com/K4ys0n/K4ys0n.github.io/master/img/gitCommand-framework.jpg)

如图所示，Remote是远程仓库，Workspace是本地工作目录，Repository是本地仓库，index（或者叫stage）是缓存。

git pull从远程仓库拉取代码到本地工作目录，做修改之后，git add添加到缓存，git commit把缓存的变动应用到本地仓库，再通过git push上传到远程仓库。

我们也可以通过git fetch复制到本地新分支或者git clone克隆到本地仓库，git checkout切换分支或撤销工作目录下的全部修改（也就是还原到上一次git add或git commit完成时的状态，即，如果缓存区有修改，则跟缓存区的修改保持一致，否则跟本地仓库保持一致）。

 ![status](https://raw.githubusercontent.com/K4ys0n/K4ys0n.github.io/master/img/gitCommand-status.jpg)

文件状态有4种，可以通过git status [文件名]来查看。

- Untracked：未跟踪，文件还在文件夹中，没有添加到版本控制中，可以用git add添加到缓存staged状态。
- Unmodified：文件已入库，未修改，表示文件夹中的文件和版本库中的一致，这时进行编辑就会变成Modified状态，或者使用git rm把版本库里的删除掉，就会变成Untracked状态。
- Modified：文件已修改，文件被编辑过，和版本库的不一致。这时git add一下就可以添加到缓存staged状态，也可以git checkout回退修改，变成没有修改过的状态，也就是Unmodified状态。
- Staged：暂存状态。使用git commit命令可以同步到版本库中，然后文件就和版本库中一致，也就是Unmodified状态。也可以git reset HEAD filename取消暂存，回退到Modified状态。

 ![add](https://raw.githubusercontent.com/K4ys0n/K4ys0n.github.io/master/img/gitCommand-add.jpg)
 
从上图可以看出，版本库的范围是包括stage和master的，也就是文件在进入缓存之前，都是在版本库之外，也就是工作区里作修改。只有变成staged状态的时候才算进入版本库，commit了才会进入本地仓库。

在工作文件夹中有一个.git的文件目录，那个就是版本库所在，版本库肯定会有一个master主分支，以及指向master的指针HEAD。

#### 2. 常见命令
```sh
# 初始化
git init    # 初始化，执行之后会在当前目录下创建一个.git文件夹

# 修改
git add [file1][file2]...    # 把文件添加到缓存区
git add .   # 添加所有文件到缓存区
git add [dir]   # 添加目录到缓存区

# 提交
git commit -m "提交的说明"   # 提交缓存区的所有修改到本地仓库
git commit -a   # 跳过add，直接进入本地仓库

# 删除
rm [file]   # 直接删除未提交文件
git rm -f [file]  # 强制删除已提交的文件，包括工作区和缓存区
git rm --cached [file]    # 已提交的文件，只删除缓存区，不删除工作区
git rm -r --cached .    # 删除本地缓存

# 撤销修改
git checkout -- [file]    # 撤销修改，返回到上次git add或git commit完成时的状态

# 文件状态
git status      # 查看git库状态

# 对比不同
git diff [file]     # 文件修改了，提交之前，可以查看修改了哪些地方

# 操作日志
git log     # 查看日志
git log -1  # 只显示一行日志
git reflog  # 查看仓库操作历史

# 回退
git reset --hard HEAD^  # 回退到当前版本的上一个版本，HEAD为当前版本，加一个^表示上一个版本
git reset --hard HEAD~1 # 与HEAD^相同，~n表示回退到上n个版本
git reset --hard 78d2   # 回退到指定版本，78d2是指定版本的版本号的前几位，版本号可以用git reflog查询

# 分支
git branch  # 查看分支
git branch [name]   # 创建分支，name为分支名
git checkout [name] # 切换到指定分支，name为分支名
git checkout -b [name]  # 创建并切换到name分支
git merge [name]  # 合并name分支到当前分支
git branch -d [name]  # 删除name分支
git branch -D [name]  # 强制删除name分支
git log --graph     # 查看分支合并图

# 远程操作
git push -u origin master   # 推送到远端仓库，-u表示第一次推送master分支，之后只需直接git push即可
git push    # 推送到远端仓库，默认origin master
git pull origin master  # 拉取远端仓库到工作目录
git pull    # 拉取远端仓库到工作目录，默认origin master
git clone [link]    # 从链接处克隆仓库到本地工作目录
 
```
git解决冲突，当我们再merge时，某个文件产生了冲突，我们可以进入那个文件手动修改，确定哪些行需要删除、哪些需要添加、哪些需要修改，然后保存之后，
再次“git add .”，“git commit -m "xxx"”即可。
## 后记
参考：

[一个小时学会Git](https://www.cnblogs.com/best/p/7474442.html#_label3_3_2_7)