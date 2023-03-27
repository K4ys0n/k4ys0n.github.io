---
layout:     post
title:      猿人学系列（二）第一届Web攻防第十二题
subtitle:   这个系列是刷猿人学平台题目的做题记录，平台地址：http://match.yuanrenxue.com/
date:       2021-02-26
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

[js加密-入门级js](http://match.yuanrenxue.com/match/12)

![image-20210226011854298](http://k4ys0n.github.io/img/image-20210226011854298.png)



## 0x02 步骤

#### 1. F12开发者模式

直接打开Network窗口，然后点击一下网站中第2页，如下：

![image-20210226011427989](http://k4ys0n.github.io/img/image-20210226011427989.png)

可以看到参数m很有可能是base64编码，找个解码网站解码得到`eXVhbnJlbnh1ZTI=`的值为`yuanrenxue2`，推测出是`yuanrenxue + 页数`的规律。

#### 2. 编写代码

直接构造代码如下：

```python
import requests
import json
import base64

def get_m(page):
    return base64.b64encode(f'yuanrenxue{page}'.encode()).decode()

def get_response(page, m):
    url = f'http://match.yuanrenxue.com/api/match/12?page={page}&m={m}'
    headers = {
        'User-Agent': 'yuanrenxue.project',
    }
    response = requests.get(url, headers=headers)
    print(response.text)
    return json.loads(response.text)

if __name__ == '__main__':
    sum = 0
    for i in range(1, 6):
        data = get_response(i, get_m(i))['data']
        for d in data:
            sum += d['value']
    print(sum)
```

输出结果如下：

![image-20210226011815764](http://k4ys0n.github.io/img/image-20210226011815764.png)

