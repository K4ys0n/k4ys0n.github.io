---
layout:     post
title:      设计模式（四）代理模式
subtitle:   根据《Python设计模式（第2版）》一书的学习，记录下来的笔记。本篇博客是代理模式，是一种结构型模式。
date:       2020-01-13
author:     K4ys0n
header-img: img/post-bg-coffee.jpeg
catalog:    true
tags:
    - 设计模式
    - Python
    - 笔记
---

## 前言
本章介绍一下代理模式，代理模式也是一种结构型设计模式。

先从代理开始理解吧。代理通常是介于寻求方和提供方之间的中介系统。寻求方是发出请求的，提供方是根据请求提供资源的。

在web世界中，代理相当于代理服务器。当客户端访问网站时，首先连接到代理服务器，向它请求资源，
代理服务器在内部评估此请求，将其发送到适当的服务器，当它收到响应后，就会将响应传递给客户端。

## 1. 代理模式定义
在设计模式中，单例是充当实际对象接口的类。对象类型可以多样化，如网络连接、内容、文件等。

代理模式的主要目的是为其他对象提供一个代理者或占位符，从而控制对实际对象的访问。

## 2. 代理模式场景
- 以简单的方式表示一个系统，如提供一个简单的接口充当客户端代理。
- 提高安全性。
- 为不同服务器上的远程对象提供本地接口，如客户端想在远程系统上运行某些命令。
- 为消耗大量内存的对象提供了一个轻量级的句柄，如个人简介头像，很大，可以先用代理预显示一个缩略图。

举个例子：制作公司想找演员拍戏，通常是跟经纪人交流，而不是跟演员交流。经纪人根据演员的日程
安排和其他合约情况，来答复制作公司该演员是否有空，以及是否对该戏感兴趣。制作公司就是客户端，
经纪人是代理，演员是资源。
```python
class Actor(object):
    def __init__(self):
        self.isBusy = False

    def occupied(self):
        self.isBusy = True
        print(type(self).__name__, "is occupied with current movie")

    def available(self):
        self.isBusy = False
        print(type(self).__name__, "is free for the movie")

    def getStatus(self):
        return self.isBusy


class Agent(object):
    def __init__(self):
        self.principal = None

    def work(self):
        self.actor = Actor()
        if self.actor.getStatus():
            self.actor.occupied()
        else:
            self.actor.available()


if __name__ == "__main__":
    r = Agent()
    r.work()
```
代理设计模式实现了对原始对象的访问控制。

它还可以用作一个层或接口，支持分布式访问。

通过增加代理，保护真正的组件不受意外的影响。

## 3. 代理模式的组成部分
三个参与者：
- **代理（Proxy）**：它是一个引用，通过它可以访问实际对象，它还提供了一个跟主题（Subject）
相同的接口，以便替代真实主题（RealSubject）。同时还负责创建和删除真实主题。
- **主题（Subject）**：定义了代理和真实主题的公共接口。（其实就是抽象基类）
- **真实主题（RealSubject）**：定义代理所代表的真实对象。

从数据结构的角度看：
- **代理**：它是控制对RealSubject类访问的类，负责处理客户端请求，创建和删除RealSubject。
- **主题/真实主题**：主题定义真实主题和代理相类似的接口，RealSubject是Subject接口的实际
实现，它提供了真正的功能，然后由客户端使用。
- **客户端**：访问Proxy类，Proxy类在内部控制对RealSubject的访问，引导客户端的请求工作。

总而言之，就是**有一个抽象基类Subject，它派生出了RealSubject，实现了基类的接口，这个时候
我们建立一个代理类Proxy，代理类也有同样的接口，这个接口用来代表RealSubject的接口，或者
控制对RealSubject类的访问。这个同样的接口可以是创造RealSubject对象来引用。**

## 4. 四种不同类型的代理
- **虚拟代理**：利用占位符暂时表示对象。比如在网站上加载图片，可以先用预览图暂时代替，以此
来节省开销。当客户端请求或访问对象时，才会创建实际对象。
- **远程代理**：给位于远程服务器或不同地址空间上的实际对象提供了一个本地表示。如在本地建立
一个远程代理对象来表示远程的对象去执行远程命令。
- **保护代理**：代理能够控制RealSubject的敏感对象的访问。
- **智能代理**：在访问对象时插入其他操作。

## 5. 代理设计模式示例：银行借记卡
假设我们要买一件衣服，可是正好手里现金不够了，这时候有一种东西叫做银行借记卡，刷一下卡，银
行就会把钱划入商家账户。

这里面就涉及：
- **客户端（You）**：提供购买衣服的方法make_payment，还有初始化函数\_\_init\_\_调用并实
例化代理。如果付款成功，将返回\_\_del\_\_方法。
- **主题（Payment）**：有一个do_pay方法用于付款，但需要代理和真实主题来实现。
- **真实主题（Bank）**：提供setCard方法用于发送借记卡信息给银行；\_\_getAccount方法用于
获取借记卡持有人的信息，我们这里假设信息就是借记卡号；\_\_hasFunds方法由于查看账户钱够不
够；do_pay方法负责付款。
- **代理（DebitCard）**：是真实主题（银行）的代理，\_\_init\_\_方法内部控制主题对象的创
建，do_pay方法提供借记卡持有人信息并支付。

```python
from abc import ABCMeta, abstractmethod


class Payment(metaclass=ABCMeta):
    @abstractmethod
    def do_pay(self):
        pass


class Bank(Payment):
    def __init__(self):
        self.card = None
        self.account = None

    def __getAccount(self):
        self.account = self.card    # Assume card number is account number
        return self.account

    def __hasFunds(self):
        print("Bank:: Checking if Account", self.__getAccount(), "has enough funds")
        return True

    def setCard(self, card):
        self.card = card

    def do_pay(self):
        if self.__hasFunds():
            print("Bank:: Paying the merchant")
            return True
        else:
            print("Bank:: Sorry, not enough funds! ")
            return False


class DebitCard(Payment):
    def __init__(self):
        self.bank = Bank()

    def do_pay(self):
        card = input("Proxy:: Punch in Card Number: ")
        self.bank.setCard(card)
        return self.bank.do_pay()


class You:
    def __init__(self):
        print("You:: Lets buy the Denim shirt")
        self.debitCard = DebitCard()
        self.isPuchased = None

    def make_payment(self):
        self.isPuchased = self.debitCard.do_pay()

    def __del__(self):
        if self.isPuchased:
            print("You:: Wow! Denim shirt is Mine :-)")
        else:
            print("You:: I should earn more :(")


you = You()
you.make_payment()
```
注意上述代码假设了资金是够的，卡号23-2134-222是随便输入的，输出结果如下：
```sh
You:: Lets buy the Denim shirt
Proxy:: Punch in Card Number: 23-2134-222
Bank:: Checking if Account 23-2134-222 has enough funds
Bank:: Paying the merchant
You:: Wow! Denim shirt is Mine :-)

Process finished with exit code 0
```

## 6. 代理模式的优点
- 可以**缓存**笨重的对象或**频繁访问的对象来提高应用程序的性能**。
- **提供对于真实主题的访问授权**，达到权限才能访问到某种资源。
- **远程代理便于**网络连接和数据库连接的**远程服务器做交互**。

## 7. 代理模式的缺点
可能会增加响应时间。

## 后记
小结一下：
- 代理设计模式：提供真实主题一样的接口，代表真实主题供客户端访问，相当于在客户端与服务
器之间增加了一层。
- 代理模式的4种实现方式：虚拟代理、远程代理、保护代理和智能代理。
- 代理模式的优点：缓存频繁访问的对象，提高应用程序性能；访问授权控制，远程代理服务。

下一章是观察者模式。