---
layout:     post
title:      猿人学系列（四）第一届Web攻防第二题
subtitle:   这个系列是刷猿人学平台题目的做题记录，平台地址：http://match.yuanrenxue.com/
date:       2021-02-27
author:     K4ys0n
header-img: img/post-bg-art.jpg
catalog:    true
tags:
    - 渗透测试
    - JS加密
    - 爬虫逆向
    - writeup
---



## 0x01 题目

[js混淆-动态cookie](http://match.yuanrenxue.com/match/2)

![image-20210227005630507](http://k4ys0n.github.io/img/image-20210227005630507.png)



## 0x02 步骤

#### 1. F12开发者模式

打开开发者模式下Network窗口，然后刷新一下页面，这道题和13题类似，都是发送三次请求来得到最终页面，第一个请求是在源码中生成cookie，接着带着这个cookie做后面的请求，但是题目提示动态cookie，一般可以理解为每次请求都需要生成并携带新的cookie。

![image-20210227010521067](http://k4ys0n.github.io/img/image-20210227010521067.png)

从做其他题目的情况可以知道，cookie中最关键的键值对是m，所以我们需要找到关于m的生成方式。同样的可以发现第一次请求看不到响应返回的源码（后面可以知道是因为它很快就重载了页面）。

#### 2. 编程查看第一个请求内容

简单写一段代码来模仿它作出第一个请求，代码如下：

```python
import requests

url = 'http://match.yuanrenxue.com/match/2'
response = requests.get(url)
print(response.text)
```

返回得到源码如下：

![image-20210227011336251](http://k4ys0n.github.io/img/image-20210227011336251.png)

可以大概看出源码经过了编码，这里用到ob混淆，可以到猿人学平台的爬虫分析工具中解混淆（注意去除script标签，链接：[解混淆测试版V0.1](http://tool.yuanrenxue.com/decode_obfuscator)），解码后可以得到js源码。

![image-20210227011607778](http://k4ys0n.github.io/img/image-20210227011607778.png)

```js
(function $c(k) {
  var B = function () {
    var Y = true;
    return function (Z, a0) {
      var a1 = Y ? function () {
        if (a0) {
          var a2 = a0["apply"](Z, arguments);
          a0 = null;
          return a2;
        }
      } : function () {};
      Y = false;
      return a1;
    };
  }();

  function C(Y, Z) {
    var a0 = (65535 & Y) + (65535 & Z);
    return (Y >> 16) + (Z >> 16) + (a0 >> 16) << 16 | 65535 & a0;
  }

  function D(Y, Z) {
    return Y << Z | Y >>> 32 - Z;
  }

  function E(Y, Z, a0, a1, a2, a3) {
    return C(D(C(C(Z, Y), C(a1, a3)), a2), a0);
  }

  function F(Y, Z, a0, a1, a2, a3, a4) {
    return E(Z & a0 | ~Z & a1, Y, Z, a2, a3, a4);
  }

  function G(Y, Z, a0, a1, a2, a3, a4) {
    return E(Z & a1 | a0 & ~a1, Y, Z, a2, a3, a4);
  }

  function H(Y, Z) {
    let a0 = [99, 111, 110, 115, 111, 108, 101];
    let a1 = "";

    for (let a2 = 0; a2 < a0["length"]; a2++) {
      a1 += String["fromCharCode"](a0[a2]);
    }

    return a1;
  }

  function I(Y, Z, a0, a1, a2, a3, a4) {
    return E(Z ^ a0 ^ a1, Y, Z, a2, a3, a4);
  }

  function J(Y, Z, a0, a1, a2, a3, a4) {
    return E(a0 ^ (Z | ~a1), Y, Z, a2, a3, a4);
  }

  function K(Y, Z) {
    if (Z) {
      return J(Y);
    }

    return H(Y);
  }

  function L(Y, Z) {
    let a0 = "";

    for (let a1 = 0; a1 < Y["length"]; a1++) {
      a0 += String["fromCharCode"](Y[a1]);
    }

    return a0;
  }

  function M(Y, Z) {
    var a2 = B(this, function () {
      var a5 = {
        "ItPLp": "return /\" + this + \"/",
        "LjPHw": "^([^ ]+( +[^ ]+)+)+[^ ]}"
      };

      var a7 = function () {
        var a8 = a7["constructor"](a5["ItPLp"])()["compile"](a5["LjPHw"]);
        return !a8["test"](a2);
      };

      return a7();
    });
    a2();
    K();
    qz = [10, 99, 111, 110, 115, 111, 108, 101, 32, 61, 32, 110, 101, 119, 32, 79, 98, 106, 101, 99, 116, 40, 41, 10, 99, 111, 110, 115, 111, 108, 101, 46, 108, 111, 103, 32, 61, 32, 102, 117, 110, 99, 116, 105, 111, 110, 32, 40, 115, 41, 32, 123, 10, 32, 32, 32, 32, 119, 104, 105, 108, 101, 32, 40, 49, 41, 123, 10, 32, 32, 32, 32, 32, 32, 32, 32, 102, 111, 114, 40, 105, 61, 48, 59, 105, 60, 49, 49, 48, 48, 48, 48, 48, 59, 105, 43, 43, 41, 123, 10, 32, 32, 32, 32, 32, 32, 32, 32, 104, 105, 115, 116, 111, 114, 121, 46, 112, 117, 115, 104, 83, 116, 97, 116, 101, 40, 48, 44, 48, 44, 105, 41, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 125, 10, 32, 32, 32, 32, 125, 10, 10, 125, 10, 99, 111, 110, 115, 111, 108, 101, 46, 116, 111, 83, 116, 114, 105, 110, 103, 32, 61, 32, 39, 91, 111, 98, 106, 101, 99, 116, 32, 79, 98, 106, 101, 99, 116, 93, 39, 10, 99, 111, 110, 115, 111, 108, 101, 46, 108, 111, 103, 46, 116, 111, 83, 116, 114, 105, 110, 103, 32, 61, 32, 39, 402, 32, 116, 111, 83, 116, 114, 105, 110, 103, 40, 41, 32, 123, 32, 91, 110, 97, 116, 105, 118, 101, 32, 99, 111, 100, 101, 93, 32, 125, 39, 10];
    eval(L(qz));

    try {
      if (global) {
        console["log"]("\u4EBA\u751F\u82E6\u77ED\uFF0C\u4F55\u5FC5python\uFF1F");
      } else {
        while (1) {
          console["log"]("\u4EBA\u751F\u82E6\u77ED\uFF0C\u4F55\u5FC5python\uFF1F");
          debugger;
        }
      }
    } catch (a5) {
      return navigator["vendorSub"];
    }
  }

  setInterval(M(), 500);

  function N(Y, Z) {
    Y[Z >> 5] |= 128 << Z % 32, Y[14 + (Z + 64 >>> 9 << 4)] = Z;

    if (qz) {
      var a0,
          a1,
          a2,
          a3,
          a4,
          a5 = 1732584193,
          a6 = -271733879,
          a7 = -1732584194,
          a8 = 271733878;
    } else {
      var a0,
          a1,
          a2,
          a3,
          a4,
          a5 = 0,
          a6 = -0,
          a7 = -0,
          a8 = 0;
    }

    for (a0 = 0; a0 < Y["length"]; a0 += 16) a1 = a5, a2 = a6, a3 = a7, a4 = a8, a5 = F(a5, a6, a7, a8, Y[a0], 7, -680876936), a8 = F(a8, a5, a6, a7, Y[a0 + 1], 12, -389564586), a7 = F(a7, a8, a5, a6, Y[a0 + 2], 17, 606105819), a6 = F(a6, a7, a8, a5, Y[a0 + 3], 22, -1044525330), a5 = F(a5, a6, a7, a8, Y[a0 + 4], 7, -176418897), a8 = F(a8, a5, a6, a7, Y[a0 + 5], 12, 1200080426), a7 = F(a7, a8, a5, a6, Y[a0 + 6], 17, -1473231341), a6 = F(a6, a7, a8, a5, Y[a0 + 7], 22, -45705983), a5 = F(a5, a6, a7, a8, Y[a0 + 8], 7, 1770010416), a8 = F(a8, a5, a6, a7, Y[a0 + 9], 12, -1958414417), a7 = F(a7, a8, a5, a6, Y[a0 + 10], 17, -42063), a6 = F(a6, a7, a8, a5, Y[a0 + 11], 22, -1990404162), a5 = F(a5, a6, a7, a8, Y[a0 + 12], 7, 1804603682), a8 = F(a8, a5, a6, a7, Y[a0 + 13], 12, -40341101), a7 = F(a7, a8, a5, a6, Y[a0 + 14], 17, -1502882290), a6 = F(a6, a7, a8, a5, Y[a0 + 15], 22, 1236535329), a5 = G(a5, a6, a7, a8, Y[a0 + 1], 5, -165796510), a8 = G(a8, a5, a6, a7, Y[a0 + 6], 9, -1069501632), a7 = G(a7, a8, a5, a6, Y[a0 + 11], 14, 643717713), a6 = G(a6, a7, a8, a5, Y[a0], 20, -373897302), a5 = G(a5, a6, a7, a8, Y[a0 + 5], 5, -701558691), a8 = G(a8, a5, a6, a7, Y[a0 + 10], 9, 38016083), a7 = G(a7, a8, a5, a6, Y[a0 + 15], 14, -660478335), a6 = G(a6, a7, a8, a5, Y[a0 + 4], 20, -405537848), a5 = G(a5, a6, a7, a8, Y[a0 + 9], 5, 568446438), a8 = G(a8, a5, a6, a7, Y[a0 + 14], 9, -1019803690), a7 = G(a7, a8, a5, a6, Y[a0 + 3], 14, -187363961), a6 = G(a6, a7, a8, a5, Y[a0 + 8], 20, 1163531501), a5 = G(a5, a6, a7, a8, Y[a0 + 13], 5, -1444681467), a8 = G(a8, a5, a6, a7, Y[a0 + 2], 9, -51403784), a7 = G(a7, a8, a5, a6, Y[a0 + 7], 14, 1735328473), a6 = G(a6, a7, a8, a5, Y[a0 + 12], 20, -1926607734), a5 = I(a5, a6, a7, a8, Y[a0 + 5], 4, -378558), a8 = I(a8, a5, a6, a7, Y[a0 + 8], 11, -2022574463), a7 = I(a7, a8, a5, a6, Y[a0 + 11], 16, 1839030562), a6 = I(a6, a7, a8, a5, Y[a0 + 14], 23, -35309556), a5 = I(a5, a6, a7, a8, Y[a0 + 1], 4, -1530992060), a8 = I(a8, a5, a6, a7, Y[a0 + 4], 11, 1272893353), a7 = I(a7, a8, a5, a6, Y[a0 + 7], 16, -155497632), a6 = I(a6, a7, a8, a5, Y[a0 + 10], 23, -1094730640), a5 = I(a5, a6, a7, a8, Y[a0 + 13], 4, 681279174), a8 = I(a8, a5, a6, a7, Y[a0], 11, -358537222), a7 = I(a7, a8, a5, a6, Y[a0 + 3], 16, -722521979), a6 = I(a6, a7, a8, a5, Y[a0 + 6], 23, 76029189), a5 = I(a5, a6, a7, a8, Y[a0 + 9], 4, -640364487), a8 = I(a8, a5, a6, a7, Y[a0 + 12], 11, -421815835), a7 = I(a7, a8, a5, a6, Y[a0 + 15], 16, 530742520), a6 = I(a6, a7, a8, a5, Y[a0 + 2], 23, -995338651), a5 = J(a5, a6, a7, a8, Y[a0], 6, -198630844), a8 = J(a8, a5, a6, a7, Y[a0 + 7], 10, 1126891415), a7 = J(a7, a8, a5, a6, Y[a0 + 14], 15, -1416354905), a6 = J(a6, a7, a8, a5, Y[a0 + 5], 21, -57434055), a5 = J(a5, a6, a7, a8, Y[a0 + 12], 6, 1700485571), a8 = J(a8, a5, a6, a7, Y[a0 + 3], 10, -1894986606), a7 = J(a7, a8, a5, a6, Y[a0 + 10], 15, -1051523), a6 = J(a6, a7, a8, a5, Y[a0 + 1], 21, -2054922799), a5 = J(a5, a6, a7, a8, Y[a0 + 8], 6, 1873313359), a8 = J(a8, a5, a6, a7, Y[a0 + 15], 10, -30611744), a7 = J(a7, a8, a5, a6, Y[a0 + 6], 15, -1560198380), a6 = J(a6, a7, a8, a5, Y[a0 + 13], 21, 1309151649), a5 = J(a5, a6, a7, a8, Y[a0 + 4], 6, -145523070), a8 = J(a8, a5, a6, a7, Y[a0 + 11], 10, -1120210379), a7 = J(a7, a8, a5, a6, Y[a0 + 2], 15, 718787259), a6 = J(a6, a7, a8, a5, Y[a0 + 9], 21, -343485441), a5 = C(a5, a1), a6 = C(a6, a2), a7 = C(a7, a3), a8 = C(a8, a4);

    return [a5, a6, a7, a8];
  }

  function O(Y) {
    var Z,
        a0 = "",
        a1 = 32 * Y["length"];

    for (Z = 0; Z < a1; Z += 8) a0 += String["fromCharCode"](Y[Z >> 5] >>> Z % 32 & 255);

    return a0;
  }

  function P(Y) {
    var a2,
        a3 = [];

    for (a3[(Y["length"] >> 2) - 1] = undefined, a2 = 0; a2 < a3["length"]; a2 += 1) a3[a2] = 0;

    var a1 = 8 * Y["length"];

    for (a2 = 0; a2 < a1; a2 += 8) a3[a2 >> 5] |= (255 & Y["charCodeAt"](a2 / 8)) << a2 % 32;

    return a3;
  }

  function Q(Y) {
    return O(N(P(Y), 8 * Y["length"]));
  }

  function R(Y) {
    var Z,
        a0,
        a1 = "0123456789abcdef",
        a2 = "";

    for (a0 = 0; a0 < Y["length"]; a0 += 1) Z = Y["charCodeAt"](a0), a2 += a1["charAt"](Z >>> 4 & 15) + a1["charAt"](15 & Z);

    return a2;
  }

  function S(Y) {
    return unescape(encodeURIComponent(Y));
  }

  function T(Y) {
    return Q(S(Y));
  }

  function U(Y) {
    return R(T(Y));
  }

  function V(Y, Z, a0) {
    M();
    return Z ? a0 ? H(Z, Y) : y(Z, Y) : a0 ? T(Y) : U(Y);
  }

  function W(Y, Z) {
    document["cookie"] = "m" + M() + "=" + V(Y) + "|" + Y + "; path=/";
    location["reload"]();
  }

  function X(Y, Z) {
    return Date["parse"](new Date());
  }

  W(X());
})();
```

#### 3. 源码分析

对上面的源码分析，首先搜索cookie，定位到cookie处，即W函数。我们知道cookie最后只需要用到形如`m=...|...`，所以不需要后面的`"; path=/"`，并且我们测试不需要重载当前页面，Z变量也没用到可以删除，并且小写字母`m`和等号`=`之间没有其他字符，所以可以判断这里`M()`返回为空字符，缩减后函数如下：

```js
function W(Y) {
    document["cookie"] = "m" + "=" + V(Y) + "|" + Y;
}
```

接着看到W在后面调用处是传入了X函数，而X函数返回时间戳，那么W函数修改如下：

```js
function W() {
    var timestamp = Date["parse"](new Date());
    document["cookie"] = "m" + "=" + V(timestamp) + "|" + timestamp;
}
```

接下来就差V函数了，`M()`肯定是空字符，没有赋值给任何变量，可以直接删了；调用V函数时我们只传入了一个变量timestamp，所以Z的值为null，a0也为null，那么return处的第一个判断就变成了false，所以返回`U(Y)`。

```js
function V(Y, Z, a0) {
    M();
    return Z ? a0 ? H(Z, Y) : y(Z, Y) : a0 ? T(Y) : U(Y);
}
```

修改后的V函数如下：

```js
function V(Y) {
    return U(Y);
}
```

做到这里继续深入看U函数，回溯的时候发现嵌套关系特别多，所以直接把相关的函数都复制到一起得了，于是如下：

```js
var qz = [10, 99, 111, 110, 115, 111, 108, 101, 32, 61, 32, 110, 101, 119, 32, 79, 98, 106, 101, 99, 116, 40, 41, 10, 99, 111, 110, 115, 111, 108, 101, 46, 108, 111, 103, 32, 61, 32, 102, 117, 110, 99, 116, 105, 111, 110, 32, 40, 115, 41, 32, 123, 10, 32, 32, 32, 32, 119, 104, 105, 108, 101, 32, 40, 49, 41, 123, 10, 32, 32, 32, 32, 32, 32, 32, 32, 102, 111, 114, 40, 105, 61, 48, 59, 105, 60, 49, 49, 48, 48, 48, 48, 48, 59, 105, 43, 43, 41, 123, 10, 32, 32, 32, 32, 32, 32, 32, 32, 104, 105, 115, 116, 111, 114, 121, 46, 112, 117, 115, 104, 83, 116, 97, 116, 101, 40, 48, 44, 48, 44, 105, 41, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 125, 10, 32, 32, 32, 32, 125, 10, 10, 125, 10, 99, 111, 110, 115, 111, 108, 101, 46, 116, 111, 83, 116, 114, 105, 110, 103, 32, 61, 32, 39, 91, 111, 98, 106, 101, 99, 116, 32, 79, 98, 106, 101, 99, 116, 93, 39, 10, 99, 111, 110, 115, 111, 108, 101, 46, 108, 111, 103, 46, 116, 111, 83, 116, 114, 105, 110, 103, 32, 61, 32, 39, 402, 32, 116, 111, 83, 116, 114, 105, 110, 103, 40, 41, 32, 123, 32, 91, 110, 97, 116, 105, 118, 101, 32, 99, 111, 100, 101, 93, 32, 125, 39, 10];
var B = function () {
    var Y = true;
    return function (Z, a0) {
        var a1 = Y ? function () {
            if (a0) {
                var a2 = a0["apply"](Z, arguments);
                a0 = null;
                return a2;
            }
        } : function () {};
        Y = false;
        return a1;
    };
}();

function C(Y, Z) {
    var a0 = (65535 & Y) + (65535 & Z);
    return (Y >> 16) + (Z >> 16) + (a0 >> 16) << 16 | 65535 & a0;
}

function D(Y, Z) {
    return Y << Z | Y >>> 32 - Z;
}

function E(Y, Z, a0, a1, a2, a3) {
    return C(D(C(C(Z, Y), C(a1, a3)), a2), a0);
}

function F(Y, Z, a0, a1, a2, a3, a4) {
    return E(Z & a0 | ~Z & a1, Y, Z, a2, a3, a4);
}

function G(Y, Z, a0, a1, a2, a3, a4) {
    return E(Z & a1 | a0 & ~a1, Y, Z, a2, a3, a4);
}

function H(Y, Z) {
    var a0 = [99, 111, 110, 115, 111, 108, 101];
    var a1 = "";

    for (var a2 = 0; a2 < a0["length"]; a2++) {
        a1 += String["fromCharCode"](a0[a2]);
    }

    return a1;
}

function I(Y, Z, a0, a1, a2, a3, a4) {
    return E(Z ^ a0 ^ a1, Y, Z, a2, a3, a4);
}

function J(Y, Z, a0, a1, a2, a3, a4) {
    return E(a0 ^ (Z | ~a1), Y, Z, a2, a3, a4);
}

function K(Y, Z) {
    if (Z) {
        return J(Y);
    }

    return H(Y);
}

function L(Y, Z) {
    var a0 = "";

    for (var a1 = 0; a1 < Y["length"]; a1++) {
        a0 += String["fromCharCode"](Y[a1]);
    }

    return a0;
}

function M(Y, Z) {
    var a2 = B(this, function () {
        var a5 = {
            "ItPLp": "return /\" + this + \"/",
            "LjPHw": "^([^ ]+( +[^ ]+)+)+[^ ]}"
        };

        var a7 = function () {
            var a8 = a7["constructor"](a5["ItPLp"])()["compile"](a5["LjPHw"]);
            return !a8["test"](a2);
        };

        return a7();
    });
    a2();
    K();
    qz = [10, 99, 111, 110, 115, 111, 108, 101, 32, 61, 32, 110, 101, 119, 32, 79, 98, 106, 101, 99, 116, 40, 41, 10, 99, 111, 110, 115, 111, 108, 101, 46, 108, 111, 103, 32, 61, 32, 102, 117, 110, 99, 116, 105, 111, 110, 32, 40, 115, 41, 32, 123, 10, 32, 32, 32, 32, 119, 104, 105, 108, 101, 32, 40, 49, 41, 123, 10, 32, 32, 32, 32, 32, 32, 32, 32, 102, 111, 114, 40, 105, 61, 48, 59, 105, 60, 49, 49, 48, 48, 48, 48, 48, 59, 105, 43, 43, 41, 123, 10, 32, 32, 32, 32, 32, 32, 32, 32, 104, 105, 115, 116, 111, 114, 121, 46, 112, 117, 115, 104, 83, 116, 97, 116, 101, 40, 48, 44, 48, 44, 105, 41, 10, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 125, 10, 32, 32, 32, 32, 125, 10, 10, 125, 10, 99, 111, 110, 115, 111, 108, 101, 46, 116, 111, 83, 116, 114, 105, 110, 103, 32, 61, 32, 39, 91, 111, 98, 106, 101, 99, 116, 32, 79, 98, 106, 101, 99, 116, 93, 39, 10, 99, 111, 110, 115, 111, 108, 101, 46, 108, 111, 103, 46, 116, 111, 83, 116, 114, 105, 110, 103, 32, 61, 32, 39, 402, 32, 116, 111, 83, 116, 114, 105, 110, 103, 40, 41, 32, 123, 32, 91, 110, 97, 116, 105, 118, 101, 32, 99, 111, 100, 101, 93, 32, 125, 39, 10];
    eval(L(qz));

    try {
        if (global) {
            console["log"]("\u4EBA\u751F\u82E6\u77ED\uFF0C\u4F55\u5FC5python\uFF1F");
        } else {
            while (1) {
                console["log"]("\u4EBA\u751F\u82E6\u77ED\uFF0C\u4F55\u5FC5python\uFF1F");
                debugger;
            }
        }
    } catch (a5) {
        return navigator["vendorSub"];
    }
}


function N(Y, Z) {
    Y[Z >> 5] |= 128 << Z % 32, Y[14 + (Z + 64 >>> 9 << 4)] = Z;

    if (qz) {
        var a0,
            a1,
            a2,
            a3,
            a4,
            a5 = 1732584193,
            a6 = -271733879,
            a7 = -1732584194,
            a8 = 271733878;
    } else {
        var a0,
            a1,
            a2,
            a3,
            a4,
            a5 = 0,
            a6 = -0,
            a7 = -0,
            a8 = 0;
    }

    for (a0 = 0; a0 < Y["length"]; a0 += 16) a1 = a5, a2 = a6, a3 = a7, a4 = a8, a5 = F(a5, a6, a7, a8, Y[a0], 7, -680876936), a8 = F(a8, a5, a6, a7, Y[a0 + 1], 12, -389564586), a7 = F(a7, a8, a5, a6, Y[a0 + 2], 17, 606105819), a6 = F(a6, a7, a8, a5, Y[a0 + 3], 22, -1044525330), a5 = F(a5, a6, a7, a8, Y[a0 + 4], 7, -176418897), a8 = F(a8, a5, a6, a7, Y[a0 + 5], 12, 1200080426), a7 = F(a7, a8, a5, a6, Y[a0 + 6], 17, -1473231341), a6 = F(a6, a7, a8, a5, Y[a0 + 7], 22, -45705983), a5 = F(a5, a6, a7, a8, Y[a0 + 8], 7, 1770010416), a8 = F(a8, a5, a6, a7, Y[a0 + 9], 12, -1958414417), a7 = F(a7, a8, a5, a6, Y[a0 + 10], 17, -42063), a6 = F(a6, a7, a8, a5, Y[a0 + 11], 22, -1990404162), a5 = F(a5, a6, a7, a8, Y[a0 + 12], 7, 1804603682), a8 = F(a8, a5, a6, a7, Y[a0 + 13], 12, -40341101), a7 = F(a7, a8, a5, a6, Y[a0 + 14], 17, -1502882290), a6 = F(a6, a7, a8, a5, Y[a0 + 15], 22, 1236535329), a5 = G(a5, a6, a7, a8, Y[a0 + 1], 5, -165796510), a8 = G(a8, a5, a6, a7, Y[a0 + 6], 9, -1069501632), a7 = G(a7, a8, a5, a6, Y[a0 + 11], 14, 643717713), a6 = G(a6, a7, a8, a5, Y[a0], 20, -373897302), a5 = G(a5, a6, a7, a8, Y[a0 + 5], 5, -701558691), a8 = G(a8, a5, a6, a7, Y[a0 + 10], 9, 38016083), a7 = G(a7, a8, a5, a6, Y[a0 + 15], 14, -660478335), a6 = G(a6, a7, a8, a5, Y[a0 + 4], 20, -405537848), a5 = G(a5, a6, a7, a8, Y[a0 + 9], 5, 568446438), a8 = G(a8, a5, a6, a7, Y[a0 + 14], 9, -1019803690), a7 = G(a7, a8, a5, a6, Y[a0 + 3], 14, -187363961), a6 = G(a6, a7, a8, a5, Y[a0 + 8], 20, 1163531501), a5 = G(a5, a6, a7, a8, Y[a0 + 13], 5, -1444681467), a8 = G(a8, a5, a6, a7, Y[a0 + 2], 9, -51403784), a7 = G(a7, a8, a5, a6, Y[a0 + 7], 14, 1735328473), a6 = G(a6, a7, a8, a5, Y[a0 + 12], 20, -1926607734), a5 = I(a5, a6, a7, a8, Y[a0 + 5], 4, -378558), a8 = I(a8, a5, a6, a7, Y[a0 + 8], 11, -2022574463), a7 = I(a7, a8, a5, a6, Y[a0 + 11], 16, 1839030562), a6 = I(a6, a7, a8, a5, Y[a0 + 14], 23, -35309556), a5 = I(a5, a6, a7, a8, Y[a0 + 1], 4, -1530992060), a8 = I(a8, a5, a6, a7, Y[a0 + 4], 11, 1272893353), a7 = I(a7, a8, a5, a6, Y[a0 + 7], 16, -155497632), a6 = I(a6, a7, a8, a5, Y[a0 + 10], 23, -1094730640), a5 = I(a5, a6, a7, a8, Y[a0 + 13], 4, 681279174), a8 = I(a8, a5, a6, a7, Y[a0], 11, -358537222), a7 = I(a7, a8, a5, a6, Y[a0 + 3], 16, -722521979), a6 = I(a6, a7, a8, a5, Y[a0 + 6], 23, 76029189), a5 = I(a5, a6, a7, a8, Y[a0 + 9], 4, -640364487), a8 = I(a8, a5, a6, a7, Y[a0 + 12], 11, -421815835), a7 = I(a7, a8, a5, a6, Y[a0 + 15], 16, 530742520), a6 = I(a6, a7, a8, a5, Y[a0 + 2], 23, -995338651), a5 = J(a5, a6, a7, a8, Y[a0], 6, -198630844), a8 = J(a8, a5, a6, a7, Y[a0 + 7], 10, 1126891415), a7 = J(a7, a8, a5, a6, Y[a0 + 14], 15, -1416354905), a6 = J(a6, a7, a8, a5, Y[a0 + 5], 21, -57434055), a5 = J(a5, a6, a7, a8, Y[a0 + 12], 6, 1700485571), a8 = J(a8, a5, a6, a7, Y[a0 + 3], 10, -1894986606), a7 = J(a7, a8, a5, a6, Y[a0 + 10], 15, -1051523), a6 = J(a6, a7, a8, a5, Y[a0 + 1], 21, -2054922799), a5 = J(a5, a6, a7, a8, Y[a0 + 8], 6, 1873313359), a8 = J(a8, a5, a6, a7, Y[a0 + 15], 10, -30611744), a7 = J(a7, a8, a5, a6, Y[a0 + 6], 15, -1560198380), a6 = J(a6, a7, a8, a5, Y[a0 + 13], 21, 1309151649), a5 = J(a5, a6, a7, a8, Y[a0 + 4], 6, -145523070), a8 = J(a8, a5, a6, a7, Y[a0 + 11], 10, -1120210379), a7 = J(a7, a8, a5, a6, Y[a0 + 2], 15, 718787259), a6 = J(a6, a7, a8, a5, Y[a0 + 9], 21, -343485441), a5 = C(a5, a1), a6 = C(a6, a2), a7 = C(a7, a3), a8 = C(a8, a4);

    return [a5, a6, a7, a8];
}

function O(Y) {
    var Z,
        a0 = "",
        a1 = 32 * Y["length"];

    for (Z = 0; Z < a1; Z += 8) a0 += String["fromCharCode"](Y[Z >> 5] >>> Z % 32 & 255);

    return a0;
}

function P(Y) {
    var a2,
        a3 = [];

    for (a3[(Y["length"] >> 2) - 1] = undefined, a2 = 0; a2 < a3["length"]; a2 += 1) a3[a2] = 0;

    var a1 = 8 * Y["length"];

    for (a2 = 0; a2 < a1; a2 += 8) a3[a2 >> 5] |= (255 & Y["charCodeAt"](a2 / 8)) << a2 % 32;

    return a3;
}

function Q(Y) {
    return O(N(P(Y), 8 * Y["length"]));
}

function R(Y) {
    var Z,
        a0,
        a1 = "0123456789abcdef",
        a2 = "";

    for (a0 = 0; a0 < Y["length"]; a0 += 1) Z = Y["charCodeAt"](a0), a2 += a1["charAt"](Z >>> 4 & 15) + a1["charAt"](15 & Z);

    return a2;
}

function S(Y) {
    return unescape(encodeURIComponent(Y));
}

function T(Y) {
    return Q(S(Y));
}

function U(Y) {
    return R(T(Y));
}

function V(Y) {
    return U(Y);
}

function get_m() {
    var timestamp = Date["parse"](new Date());
    return "m" + "=" + V(timestamp) + "|" + timestamp;
}
```

注意最外层的函数外套直接去了，因为没用，直接运行；另外将`setInterval(M(), 500);`直接删去，这通常是设置断点用的；还要将`let`都替换成`var`；用`鬼鬼js调试工具`调试发现还需要设置全局变量qz，这个在源码里都有，直接复制一份赋值给全局变量就行，我放在第一行了；最后将W函数改名为`get_m`并直接将cookie返回。

将上述代码保存在day2.js文件中。

#### 4. 编写代码

编写代码如下，每次用新生成的cookie来访问api即可：

```python
import requests
import re
import json
import execjs

def get_cookie():
    with open('day2.js', 'r', encoding='utf-8') as f:
        data = f.read()
        m = execjs.compile(data).call('get_m')
    return m

def get_response(m, page):
    url = f'http://match.yuanrenxue.com/api/match/2?page={page}'
    headers = {
        'User-Agent': 'yuanrenxue.project',
        'Cookie': m
    }
    response = requests.get(url, headers=headers)
    print(response.text)
    return json.loads(response.text)

if __name__ == '__main__':
    sum = 0
    for i in range(1, 6):
        data = get_response(get_cookie(), i)['data']
        for d in data:
            sum += d['value']
    print(sum)
```

输出结果如下：

![image-20210227015206924](http://k4ys0n.github.io/img/image-20210227015206924.png)