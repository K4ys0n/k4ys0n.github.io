---
layout:     post
title:      设计模式（六）命令模式
subtitle:   根据《Python设计模式（第2版）》一书的学习，记录下来的笔记。本篇博客是命令模式，是一种行为型模式。
date:       2020-03-16
author:     K4ys0n
header-img: img/post-bg-coffee.jpeg
catalog:    true
tags:
    - 设计模式
    - Python
    - 笔记
---

## 前言
命令设计模式的对象用于封装在完成一项操作时或在触发一个时间时所需的全部信息（包括方法名称、拥有方法的对象、方法参数的值）。

命令模式实际上是**封装了调用**

举个例子，安装向导。安装向导通过多个步骤或屏幕来了解用户的偏好。当用户使用向导时，用户需要作出某些选择，那么这个向导可以用命令模
式来实现。向导（Command对象），用户在向导的多个步骤中制定的选项存储在Command对象中，当用户在向导的最后一个屏幕上单击Finish按钮
时，Command对象就会运行execute方法，该方法会考察所有存储的选项并完成所有信息被封装在稍后用于采取动作的对象中。


## 1. 命令设计模式常用术语
Command、Receiver、Invoker和Client。

Command对象了解Receiver对象的情况，能调用Receiver对象的方法。
调用者方法的参数值存储在Command对象中，调用者知道如何执行命令。
客户端用来创建Command对象并设置其接收者。

## 2. 命令模式的主要意图：
- 将请求封装成对象。
- 可用不同的请求对客户进行参数化。
- 允许将请求保存在队列中。
- 提供面向对象的回调。

## 3. 命令模式场景
- 根据需要执行的操作对对象进行参数化。
- 将操作添加到队列并在不同地点执行请求。
- 创建一个结构来根据较小操作完成高级操作。
- 重做或回滚操作：首先在文件系统或内存中创建快照，当贝要求回滚时，恢复到该快照；使用命令模式时，可以存储命令序列，并且要求进行重
做时，重新运行相同的一组操作即可。
- 异步任务执行：在分布式系统中，通常要求设备具备异步执行任务的功能，以便核心服务在大量请求涌来时不会阻塞；在命令模式中，Invoker
对象可以维护一个请求队列，并将这些任务发送到Receiver对象，以便它们可以独立于主应用程序线程来完成相应的操作。

安装向导示例代码，创建Wizard对象，用preferences方法存储用户在向导的各个屏幕期间作出的选择，提供execute方法供完成向导时执行。
```python
class Wizard:
    def __init__(self, src, rootdir):
        self.choices = []
        self.rootdir = rootdir
        self.src = src

    def preferences(self, command):
        self.choices.append(command)

    def execute(self):
        for choice in self.choices:
            if list(choice.values())[0]:
                print("Copying binaries --", self.src, " to ", self.rootdir)
            else:
                print("No Operation")


if __name__ == "__main__":
    # client code
    wizard = Wizard("python3.6.gzip", '/usr/bin/')
    # Users chooses to install Python only
    wizard.preferences({'python': True})
    wizard.preferences({'java': False})
    wizard.execute()
```

## 4. 命令模式的组成部分
- Command：声明执行操作的接口。
- ConcreteCommand：将一个Receiver对象和一个操作绑定在一起。
- Client：创建ConcreteCommand对象并设定其接收者。
- Invoker：要求该ConcreteCommand执行这个请求。
- Receiver：知道如何实施与执行一个请求相关的操作。

示例：
```python
from abc import ABCMeta, abstractmethod

class Command(metaclass=ABCMeta):
    def __init__(self, recv):
        self.recv = recv

    def execute(self):
        pass

class ConcreteCommand(Command):
    def __init__(self, recv):
        self.recv = recv

    def execute(self):
        self.recv.action()

class Receiver:
    def action(self):
        print('Receiver Action')

class Invoker:
    def command(self, cmd):
        self.cmd = cmd

    def execute(self):
        self.cmd.execute()


if __name__ == "__main__":
    recv = Receiver()
    cmd = ConcreteCommand(recv)
    invoker = Invoker()
    invoker.command(cmd)
    invoker.execute()
```

## 5. 命令模式实例：证券交易所
作为用户，会创建买入或卖出股票的订单，通常情况下，用户无法直接执行买入或卖出，而是由代理或经纪人。
假设想在周一早上开市后卖出股票，那可以在周日向代理提出卖出股票的请求，然后由代理放入排队，在开市的
时候执行，完成交易。
- Order：也就是Command类，来定义客户端下达的订单。
- 具体的订单：也就是ConcreteCommand类，来买卖股票。
- 接收者：也就是Receiver类，来定义实际执行交易接收者。
- 调用者：也就是Invoker类，接收订单并交由接收者执行的代理。

代码如下：
```python
from abc import ABCMeta, abstractmethod
class Order(metaclass=ABCMeta):
    @abstractmethod
    def execute(self):
        pass

class BuyStockOrder(Order):
    def __init__(self, stock):
        self.stock = stock

    def execute(self):
        self.stock.buy()

class SellStockOrder(Order):
    def __init__(self, stock):
        self.stock = stock

    def execute(self):
        self.stock.sell()

class StockTrade:
    def buy(self):
        print("You will buy stocks")

    def sell(self):
        print("You will sell stocks")

class Agent:
    def __init__(self):
        self.__orderQueue = []

    def placeOrder(self, order):
        self.__orderQueue.append(order)
        order.execute()


if __name__ == "__main__":
    # client
    stock = StockTrade()
    buyStock = BuyStockOrder(stock)
    sellStock = SellStockOrder(stock)
    # invoker
    agent = Agent()
    agent.placeOrder(buyStock)
    agent.placeOrder(sellStock)
```

## 6. 命令模式的优缺点
优点：
- 将调用操作的类与指导如何执行该操作的对象解耦。
- 提供队列系统后，可以创建一系列命令。
- 添加新命令更加容易，并且无需更改现有代码。
- 可以使用命令模式来定义回滚系统。

缺点：
- 需要大量的类和对象进行协作。
- 每个单独的命令都是一个ConcreteCommand类，从而增加了需要实现和维护的类的数量。

## 后记
小结一下：
- 命令模式的组成部分：Command、ConcreteCommand、Receiver、Invoker和Client。
- 如何使用命令模式来封装在稍后某个时间点触发事件或动作所需的所有信息。
- 命令模式的优缺点：解耦，添加命令方便，但需要很多类，维护麻烦。

下一章是模板方法模式。

