---
layout:     post
title:      设计模式（三）门面模式
subtitle:   根据《Python设计模式（第2版）》一书的学习，记录下来的笔记。本篇博客是门面模式，是一种结构型模式。
date:       2020-01-10
author:     K4ys0n
header-img: img/post-bg-coffee.jpeg
catalog:    true
tags:
    - 设计模式
    - Python
    - 笔记
---

## 前言
门面设计模式是一种结构型模式，什么是结构型模式呢？
- 结构型模式描述如何将对象和类组合成更大的结构。
- 是一种简化设计工作的模式。
- 类模式可以通过继承来描述抽象，从而提供更有用的程序接口，而对象模式则描述了如何将对象联
系起来从而组合成更大的对象。结构型模式是类和对象模式的综合体。

结构型模式例子：
- 门面模式
- 适配器模式
- 桥接模式
- 装饰器模式

感觉门面模式甚至都不能算作一种模式，个人理解更像是把复杂的各种类和对象进行规划，根据功能
或者用途进行分门别类，然后提炼成接口(或者说方法)，减少我们每次都要去找相应细节内容。

本章源码链接：[https://github.com/K4ys0n/design-pattern/blob/master/facadePattern.py](https://github.com/K4ys0n/design-pattern/blob/master/facadePattern.py)

## 1. 门面设计模式的定义
门面模式其实就是隐藏内部系统复杂性的同时，提供给客户端一个接口，以便它们可以非常轻松地访
问系统。

它为子系统的一组接口提供一个统一的接口，并定义一个高级接口来帮助客户端通过更加简单的方式
使用子系统。

**它不是一种封装，而是一种组合**。因为客户端还是可以直接访问子系统，门面只是一种建议。

促进了实现**与多个客户端的解耦**。

举个例子：去杂货店买东西，我们直接问店长买某个东西，那么店长就相当于门面。

## 2. 门面模式示例
**婚礼安排**：假设我要举行一场婚礼，我要张罗一切：订酒店、交代餐饮、布置场景、安排背景音乐。
这些我完全可以找一个负责人来帮我做，这个负责人就是门面，他将负责跟各个提供商交涉，并帮我争取
最优惠的价格。
- 客户端：我需要在婚礼前完成所有准备工作。
- 门面：负责人负责与所有相关人员进行交涉。
- 子系统：代表提供餐饮、酒店管理和花卉装饰等服务的系统。

那么负责人具体要干什么事呢？我们这里规定了四项工作：
- 预定酒店（Hotelier类），它有一个方法，用于检查当天是否有免费酒店（\_\_isAvailable）。
- 花卉装饰（Florist类），指定要使用哪些种类的花(setFlowerRequirements)。
- 安排餐饮（Caterer类），指定婚宴的菜肴类型（setCuisine）。
- 安排音乐（Musician类），设置音乐类型（setMusicType）。

客户端访问负责人时，负责人依次做完这些事即可。

```python
class EventManager(object):
    def __init__(self):
        print("Event Manager:: Let me talk to the folks\n")

    def arrange(self):
        self.hotelier = Hotelier()
        self.hotelier.bookHotel()
        self.florist = Florist()
        self.florist.setFlowerRequirements()
        self.caterer = Caterer()
        self.caterer.setCuisine()
        self.musician = Musician()
        self.musician.setMusicType()


class Hotelier(object):
    def __init__(self):
        print("Arranging the Hotel for Marriage? --")

    def __isAvailable(self):
        print("Is the Hotel free for the event on given day? ")
        return True

    def bookHotel(self):
        if self.__isAvailable():
            print("Registered the Booking\n\n")


class Florist(object):
    def __init__(self):
        print("Flower Decorations for the Event? --")

    def setFlowerRequirements(self):
        print("Carnatiions, Roses and Lilies would be used for Decorations\n\n")


class Caterer(object):
    def __init__(self):
        print("Food Arrangements for the Event --")

    def setCuisine(self):
        print("Chinese & Continental Cuisine to be served\n\n")

class Musician(object):
    def __init__(self):
        print("Musical Arrangements for the Marriage --")

    def setMusicType(self):
        print("Jazz and Classical will be played\n\n")


class You(object):
    def __init__(self):
        print("You:: Whoa! Marriage Arrangements??!!!")

    def askEventManager(self):
        print("You:: Let's Contact the EventManager\n\n")
        em = EventManager()
        em.arrange()

    def __del__(self):
        print("You:: Thanks to Event Manager, all preparations done!Phew! ")


you = You()
you.askEventManager()
```

## 3. 最少知识原则
门面模式的作用是促进客户端和子系统的解耦。其背后的设计原理就是最少知识原则。

**最少知识原则指导我们减少对象之间的交互**。

- 设计系统时，对于创建的每个对象，都应该考察与之交互的类的数量，以及交互方式。
- 避免创建许多彼此紧密耦合的类的情况。
- 如果类之间存在大量依赖关系，那么系统很难维护；修改一部分很容易导致其他部分被动改变，
应坚决避免。

但是缺点是有可能建立了不必要的接口，反而加重了系统的复杂性。

## 后记
小结一下：
- 门面设计模式：将子系统的多个接口组合起来，创建一个简单的接口供客户使用。
- 门面设计模式的作用：极大简化了子系统的复杂性，但并不是封装，而是组合，客户端还是可以
直接访问子系统的接口。
- 最少知识原则：尽量减少对象之间的交互，尽量去统一接口，但不能过度。

下一章是代理模式。

源码链接：[https://github.com/K4ys0n/design-pattern/blob/master/facadePattern.py](https://github.com/K4ys0n/design-pattern/blob/master/facadePattern.py)