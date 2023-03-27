---
layout:     post
title:      猿人学系列（七）第一届Web攻防第十五题
subtitle:   这个系列是刷猿人学平台题目的做题记录，平台地址：http://match.yuanrenxue.com/
date:       2021-02-28
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

[骚操作-备周则意怠-常见则不疑](http://match.yuanrenxue.com/match/15)

![image-20210228141131786](http://k4ys0n.github.io/img/image-20210228141131786.png)



## 0x02 步骤

#### 1. F12开发者模式

打开开发者模式，刷新页面，查看api请求，请求不仅带着page参数，还带着m参数，而且由两个`%7c`隔开的三段字符，感觉很可疑，如下：

![image-20210228162314897](http://k4ys0n.github.io/img/image-20210228162314897.png)

刷新第2页，发送的api请求携带的m值不一样，但是格式类似，可以猜测是每次都依据一定规则生成的。

#### 2. 源码分析

到源码中搜索一下关键字`api/match/15`，如下：

![image-20210228162705525](http://k4ys0n.github.io/img/image-20210228162705525.png)

可以看到m是由`window.m()`，而`window.m()`中又用到了`window.q`，这个函数回溯看到是请求了一个wasm文件，并从中解析出了`encode`函数赋给`window.q`。

因此编写一个脚本去获取wasm文件。

#### 3. 编写脚本

这里是百度搜到了python有一个库可以解析这种文件，`pywasm`库。

```python
import requests
import pywasm

def get_wasm():
    url = 'http://match.yuanrenxue.com/static/match/match15/main.wasm'
    response = requests.get(url)
    with open("day15.wasm", 'wb') as f:
        f.write(response.content)
    return pywasm.load("day15.wasm")

if __name__ == '__main__':
    wasm = get_wasm()
```

接下来仿照m的生成代码，编写python脚本，如下：

![image-20210228163822175](http://k4ys0n.github.io/img/image-20210228163822175.png)

```python
import math
import random

def get_m(wasm):
    t1 = int(int(time.time()) / 2)
    t2 = int(int(time.time()) / 2 - math.floor(random.random() * 50 + 1))
    q = wasm.exec("encode", [t1, t2])
    return f'{q}|{t1}|{t2}'
```

最后用生成的m构造链接去构造api请求，如下：

```python
import requests
import pywasm
import random
import time
import math
import json

def get_wasm():
    url = 'http://match.yuanrenxue.com/static/match/match15/main.wasm'
    response = requests.get(url)
    with open("day15.wasm", 'wb') as f:
        f.write(response.content)
    return pywasm.load("day15.wasm")

def get_m(wasm):
    t1 = int(int(time.time()) / 2)
    t2 = int(int(time.time()) / 2 - math.floor(random.random() * 50 + 1))
    q = wasm.exec("encode", [t1, t2])
    return f'{q}|{t1}|{t2}'

def get_response(page, m):
    url = f'http://match.yuanrenxue.com/api/match/15?m={m}&page={page}'
    headers = {
        'User-Agent': 'yuanrenxue.project'
    }
    response = requests.get(url, headers=headers)
    return json.loads(response.text)

if __name__ == '__main__':
    wasm = get_wasm()
    m = get_m(wasm)
    sum = 0
    for i in range(1, 6):
        data = get_response(i, m)['data']
        for d in data:
            sum += d['value']
    print(sum)
```

输出结果为：

![image-20210228164351138](http://k4ys0n.github.io/img/image-20210228164351138.png)

