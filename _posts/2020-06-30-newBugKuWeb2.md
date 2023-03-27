---
layout:     post
title:      新BugKu平台web题writeup(下)
subtitle:   新Bugku平台，又名newbugku，打靶CTF，CTF_论剑场。包含题目web25、web8、web22、web27、web12、web24、web10、web19、web16。
date:       2020-06-30
author:     K4ys0n
header-img: img/post-bg-coffee.jpeg
catalog:    true
tags:
    - CTF
    - web
    - writeup
    - 网络安全
---

## web25
打开链接后看到有个下载的按钮，点击进去，点下载但没有反应，查看源码，源码中有个/2/ziidan.txt的链接，但是跳转过去是404，随便是了一下把/2删掉，直接跳转/ziidan.txt发现返回了下面这个东西：
```
asdhjk
dakjhkjwq
adkjhsdk
fkdjknbv
dkajshdlj
hjsjnb
sdalkj
flagf
sfksjhwqe
dsalkjlkqjwe
hsjnb
```
尝试这爆破一个一个输入到一开始那个链接的输入框中，但是都不行。

接下来用御剑扫描了一下路径发现有shell.php和flag.php，打开shell.php是另一个输入框，于是也试着爆破一下，发现在hsjnb字符串输入之后，得到flag如下：
```
flag{ee90585a68b88bcd}
```

## web8
## web22
## web27
## web12
## web24
## web10
这道题主要涉及JWT，JWT分为三个部分，Header头部（字典字符串，包含JWT标志和加密算法）、Payload（字典字符串，包含一系列自己设置的键值对信息，以及创建时间和过期时间）、Signature（字典字符串，Header和Payload用点号连起来的字符串，然后用用户设置的秘钥进行sha256加密的字符串，可对秘钥先进行base64加密再sha256）。

这里会用到一个在线网站可以进行修改，https://jwt.io 网站首页下拉一点有Encoded和Decoded。

好了，回到题目，首先看到的是输入框，查看源码发现有串字符串：NNVTU23LGEZDG===，有等号所以进行base64解码，但是失败了，于是试下base32解码，得到kk:kk123，因此拿到前面输入框，username输入kk，password输入kk123。

返回页面提示到要登录L3yx的账号，再加上有关JWT，所以burpsuite拦截看看：先用kk和kk123登录后，设置代理，然后刷新得到请求包，看到token字段类似下面这串
```
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJMM3l4IiwiaWF0IjoxNTkzNDk4NzA5LCJleHAiOjE1OTM0OTg3MTQsImFjY291bnQiOiJrayJ9.iWe-quPG3tGMxGi7vx7UBYvrTVjbJYIy9RHfTB11fag
```
粘贴到上面提到的网站https://jwt.io 中的Encoded处，得到Decoded如下
```
HEADER:ALGORITHM & TOKEN TYPE
{
  "typ": "JWT",
  "alg": "HS256"
}
PAYLOAD:DATA
{
  "iss": "L3yx",
  "iat": 1593498709,
  "exp": 1593498714,
  "account": "kk"
}
VERIFY SIGNATURE
HMACSHA256(
  base64UrlEncode(header) + "." +
  base64UrlEncode(payload),
  # 这里要填秘钥
)
```
把Payload中account字段的值kk改为L3yx，iat改小一点(如1593490000，比原来的小就行)，exp改大一点(如1593500000)。但问题在于下面有个秘钥，现在我们还不知道。

想到前面返回的kk的日记里说到用了vim写网站主页崩了，但还在用
```
L3yx这家伙上次说vim一点都不好用，他写这个网站主页的时候还突然崩了，但他现在还不是在用，真香！
他好像还在这网站写了什么秘密，我一定要登他账号上去看看!
```
尝试/index.php但不行，那直接访问/根目录，居然可以，
```
Index of /
[ICO]	Name	Last modified	Size	Description
[ ]	L3yx.php	2018-12-06 16:35 	1.1K	 
[ ]	L3yx.php.swp	2018-12-07 07:32 	12K	 
[DIR]	src/	2018-12-07 02:34 	- 	 
[ ]	user.php	2018-12-07 02:32 	1.6K	 
Apache/2.4.10 (Debian) Server at 123.206.31.85 Port 3032
```
有L3yx.php.swp文件，下载下来用记事本打开，找到了里面存在一个
```
KEY = 'L3yx----++++----'
```
所以在上面JWT处填写秘钥处填上L3yx----++++----，然后保存编码后的JWT，替换掉拦截下来的token值，然后发送出去即可得到返回包，即flag为
```
flag{32ef489b73c4362ca6f28b7e7cf88368}
```

## web19
## web16