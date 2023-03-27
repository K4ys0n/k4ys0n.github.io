---
layout:     post
title:      设计模式（五）观察者模式
subtitle:   根据《Python设计模式（第2版）》一书的学习，记录下来的笔记。本篇博客是观察者模式，是一种行为型模式。
date:       2020-03-13
author:     K4ys0n
header-img: img/post-bg-coffee.jpeg
catalog:    true
tags:
    - 设计模式
    - Python
    - 笔记
---

## 前言
行为型模式，主要关注的是对象的责任，用来处理对象之间的交互。

行为型模式建议对象之间应该能够彼此交互，同时还要松散耦合。

观察者模式是行为型模式的一种。

观察者实际上是**了解对象的情况**。

## 1. 观察者模式定义
观察者设计模式，对象（主题）维护了一个依赖（观察者）列表，以便主题可以使用观察者定义
的任何方法通知所有观察者它所发生的变化。

## 2. 代理模式场景
通常用于广播或者订阅系统，比如博客订阅，当发布新博客时，订阅者会收到通知。

还可以用于：
- 在分布式系统中实现事件服务。
- 用作新闻机构的框架。
- 股票市场也是观察者模式的一个大型场景。

示例一下：
```python
class Subject:
    def __init__(self):
        self.__observers = []

    def register(self, observer):
        self.__observers.append(observer)

    def notifyAll(self, *args, **kwargs):
        for observer in self.__observers:
            observer.notify(self, *args, **kwargs)


class Observer1:
    def __init__(self, subject):
        subject.register(self)

    def notify(self, subject, *args):
        print(type(self).__name__, ':: Got', args, 'From', subject)


class Observer2:
    def __init__(self, subject):
        subject.register(self)

    def notify(self, subject, *args):
        print(type(self).__name__, ':: Got', args, 'From', subject)


subject = Subject()
observer1 = Observer1(subject)
observer2 = Observer2(subject)
subject.notifyAll("notification")
```

## 3. 观察者模式的组成部分
观察者模式的组成部分：主题、观察者、具体观察者
- 主题（Subject）：类Subject需要了解Observer，然后提供一些注册方法，一个Subject可以处理多个Observer。
- 观察者（Observer）：为关注主题的对象定义了一个接口，并且定义了Observer需要实现的各个方法，以便在主题发生变化时能够获得相应的通知。
- 具体观察者（ConcreteObserver）：用来保存应该与Subject的状态保持一致的状态，实现了Observer接口以保持其状态与主题中的变化一致。

简单来说就是具体观察者继承了观察者这个类，然后实现类方法，向主题注册自己，之后当主题发生变化时，主题会通知所有注册的观察者。

## 4. 观察者模式示例：新闻订阅
主题就是新闻发布类（NewsPublisher），提供attach方法供用户注册，提供subscriber方法返回已注册的用户列表，notifySubscriber方法用来广播通知，addNews方法用来新建新闻，getNews方法用来犯规最新消息。

用户也就是观察者（Subscriber）是一个抽象基类，提供update方法来接收通知。

根据Subscriber类设计了三种具体观察者：EmailSubscriber、SMSSubscriber和AnyotherSubscriber，它们都实现了update方法。

代码如下：
```python
class NewsPublisher:
    def __init__(self):
        self.__subscribers = []
        self.__latestNews = None

    def attach(self, subscriber):
        self.__subscribers.append(subscriber)

    def detach(self):
        return self.__subscribers.pop()

    def subscribers(self):
        return [type(x).__name__ for x in self.__subscribers]

    def notifySubscribers(self):
        for sub in self.__subscribers:
            sub.update()

    def addNews(self, news):
        self.__latestNews = news

    def getNews(self):
        return "Got News:" + self.__latestNews


from abc import ABCMeta, abstractmethod, ABC


class Subscriber(metaclass=ABCMeta):
    @abstractmethod
    def update(self):
        pass


class SMSSubscriber(Subscriber):
    def __init__(self, publisher):
        self.publisher = publisher
        self.publisher.attach(self)

    def update(self):
        print(type(self).__name__, self.publisher.getNews())


class EmailSubscriber(Subscriber):
    def __init__(self, publisher):
        self.publisher = publisher
        self.publisher.attach(self)

    def update(self):
        print(type(self).__name__, self.publisher.getNews())


class AnyotherSubscriber(Subscriber):
    def __init__(self, publisher):
        self.publisher = publisher
        self.publisher.attach(self)

    def update(self):
        print(type(self).__name__, self.publisher.getNews())


if __name__ == "__main__":
    news_publisher = NewsPublisher()
    for Subscriber in [SMSSubscriber, EmailSubscriber, AnyotherSubscriber]:
        Subscriber(news_publisher)
    print("\nSubscribers:", news_publisher.subscribers())
    news_publisher.addNews("Hello world!")
    news_publisher.notifySubscribers()
    print("\nDetached:", type(news_publisher.detach()).__name__)
    print("\nSubscribers:", news_publisher.subscribers())
    news_publisher.addNews("My second news!")
    news_publisher.notifySubscribers()
```

## 5. 观察者模式的通知方式
- 拉模型：拉模型比较被动、效率低，步骤是主题通知观察者，然后观察者从主题那里提取所需数据。
- 推模型：推模型由主题主导，但是有可能推很多用不到的数据导致响应时间慢，步骤是主题通知观察者的同时携带所有数据。

## 6. 松耦合
耦合是指一个对象对于与其交互的其他对象的了解程度。松耦合的目的是争取在彼此交互的对象之间实现松散耦合设计。

松耦合降低了再一个元素内发生的更改可能对其他元素产生意外影响的风险，使得测试、维护和故障排除工作更加简单，系统可以轻松地分解为可定义的元素。

观察者模式的松散耦合体现在：
- 主题只知道也只需要知道观察者的一个特定接口，也不需要了解具体观察者。
- 可以随时添加任意的新观察者。
- 添加新的观察者时，不需要修改主题。
- 观察者或主题没有绑定在一起，所以可以独立使用。
- 主题或观察者中的变化不会相互影响。

## 7. 观察者模式的优缺点
优点：
- 对象之间松散耦合。
- 可以随时增删观察者。
- 可以在无需对主题或观察者进行任何修改的情况下高效地发送数据到其他对象。

缺点：
- 观察者接口必须由具体观察者实现，而这涉及继承。
- 实现不当的话可能增加复杂性，导致性能降低。
- 在软件应用中有时可能是不可靠的，会导致竞争条件或不一致性。

## 后记
小结一下：
- 观察者模式基础知识：主题、观察者、具体观察者。
- 两种实现方式：拉模型和推模型。
- 松散耦合原理：个人理解就是尽量让对象之间的耦合度降低，能够各自独立使用。

下一章是命令模式。

