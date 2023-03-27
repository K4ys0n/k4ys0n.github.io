---
layout:     post
title:      Web笔记（十四）PHP常见特性
subtitle:   这个系列是整理学习安全的笔记，包括Web和PWN的一些知识。本章是php一些容易常见的容易被利用攻击的特性。
date:       2020-12-06
author:     K4ys0n
header-img: img/post-bg-rwd.jpg
catalog:    true
tags:
    - CTF
    - web
    - 网络安全
    - 学习笔记
    - php
---



## 0x01 and和&&运算符

and的优先级 小于 = 小于 \&\&

- and如果是要赋值给变量，那就会先把and前面的逻辑结果赋值给变量，再进行逻辑运算，例如：`$a=1 and 0;` 则a为True

- \&\&则是先运算再赋值，例如：`$a=1 && 0;` 则a为False



## 0x02 \$args和\$\$args
- \$args为取变量的值
- \$\$args：变量args的值正好是另一个变量的名字，那么相当于取另一个变量的名字，例如：
```php
$a='b';
$b='hello';
echo $$a;	// 输出结果为hello
```

当服务器代码存在php的九大全局变量时都可以试一试，用$args进行变量覆盖：

- \$_POST    用于接收POST提交的数据
- \$_GET    用于获取URL地址栏的参数数据
- \$_FILES    用于文件就收的处理img，最常见
- \$_COOKIE    用于获取与setCookie()中的name 值
- \$_SESSION    用于存储session的值或获取session中的值
- \$_REQUEST    具有get,post的功能，但比较慢
- \$_SERVER    是预定义服务器变量的一种
- \$GLOBALS    一个包含了全部变量的全局组合数组
- \$_ENV    是一个包含服务器端环境变量的数组。它是PHP中一个超级全局变量，可以在PHP 程序的任何地方直接访问它



## 0x03 弱等于号“==”

有弱等于，对应就有强等于“===”。

- false==""==0==NULL     //true
- "admin1"==0);   //true
- "1admin"==1);   //true
- "0e123456"=="0e4456789"    //true
- "0x1e240"=="123456"   //true
- 0=="0e4456789"    //true
- [false]==[0]    //true
- "0x1e240"=="123456"==123456   //true



## 0x04 类型转换

- md5(['a'])===md5(['b'])     对数组md5会返回NULL
- strcmp([], 'a')===NULL    PHP>5.3版本数组和字符串比较会返回NULL
- in_array('abc',[0])===true    'abc'会被强制类型转换
- is_numeric('0e1')===true    科学计数法
- in_array('abc',[0,1,2])===true    in_array函数比较时会使用弱等于（'abc'==0）



## 0x05 正则表达式（ereg/eregi）

- 字符串对比解析，当ereg读取字符串string时，%00后面的字符串不会被解析。这里a=abcd%001234，可以绕过。
- 如果传入数组，ereg返回NULL



## 0x06 变量覆盖

#### 1. 变量覆盖漏洞产生

- 变量如果未初始化，且能被用户所控制。
- 在php中，若register_globals为on时尤其严重，此为全局变量覆盖漏洞。
- 当register_global=ON时，变量来源可能是各个不同的地方，比如页面的表单、cookie等。

#### 2. 变量覆盖漏洞相关函数

- extract()函数从数组中把变量导入到当前的符号表中。对于数组中的每个元素，键名用于变量名，键值用于变量值。

- parse_str()的作用是解析字符串，并注册成变量。与parse_str()类似的函数还有mb_parse_str()，parse_str()将字符串解析成多个变量，如果参数str是URL传递入的查询字符串（query string），则将它解析为变量并设置到当前作用域。如：`parse_str($_SERVER["QUERY_STRING"]);`

- \$\$会把变量本身的key当做名字，value当做变量值。如：\$key="\_CONFIG"，那么\$\$key就相当于\$\_CONFIG。
```php
<?php
    $a = '0';
	extract($_GET);
	if($a==1){
        echo "success";
    }else{
        echo "failed";
    }
?>
```

访问http://127.0.0.1/xx.php?a=1，显示success表示完成变量覆盖。