---
layout:     post
title:      设计模式（七）模板方法模式
subtitle:   根据《Python设计模式（第2版）》一书的学习，记录下来的笔记。本篇博客是模板方法模式，是一种行为型模式。
date:       2020-03-17
author:     K4ys0n
header-img: img/post-bg-coffee.jpeg
catalog:    true
tags:
    - 设计模式
    - Python
    - 笔记
---

## 前言
模板方法模式是一种行为设计模式，通过一种称为模板方法的方式来定义程序框架或算法。如制作饮料的步骤。

还通过将步骤中的一些实现推迟到子类来帮助定义或定制算法的某些步骤，这也意味着子类可以重新定义自己的行为。

模板方法模式是封装算法。

## 1. 模板方法模式的适用场景
- 在多个算法或类实现类似或相同逻辑的时候。
- 在子类实现算法有助于减少重复代码的时候。
- 可以让子类利用覆盖实现行为来定义多个算法的时候。

例如，煮咖啡和煮茶都需要烧水；计算机语言使用的编译器都需要做手机源代码并将其编译为目标对象这两件事。

## 2. 模板方法模式的主要意图：
- 使用基本操作定义算法的框架。
- 重新定义子类的某些操作，无需修改算法的结构。
- 实现代码重用并避免重复工作。
- 利用通用接口或实现。

## 3. 模板方法模式组成部分
- AbstractClass：声明一个定义算法步骤的接口。
- ConcreteClass：定义子类特定的步骤。
- template_method()：通过调用步骤方法来定义算法。

用编译器的例子来举例，首先定义collectSource()和compileToObject()抽象方法分别实现收集源代码和编译成目标代码。
然后，定义run()负责执行程序，该算法是由compileAndRun()方法来定义的。接着，让具体类iOSCompiler实现抽象方法，
在编译后运行Swift（iOS开发语言）代码。
```python
from abc import ABCMeta, abstractmethod

class Compiler(metaclass=ABCMeta):
    @abstractmethod
    def collectSource(self):
        pass

    @abstractmethod
    def compileToObject(self):
        pass

    @abstractmethod
    def run(self):
        pass

    def compilerAndRun(self):
        self.collectSource()
        self.compileToObject()
        self.run()

class iOSCompiler(Compiler):
    def collectSource(self):
        print("Collecting Swift Source Code")

    def compileToObject(self):
        print("Compiling Swift code to LLVM bitcode")

    def run(self):
        print("Program running on runtime environment")


iOS = iOSCompiler()
iOS.compilerAndRun()
```

再举个简单例子：
```python
from abc import ABCMeta, abstractmethod

class AbstractClass(metaclass=ABCMeta):
    def __init__(self):
        pass

    @abstractmethod
    def operation1(self):
        pass

    @abstractmethod
    def operation2(self):
        pass

    def template_method(self):
        print("Defining the Algorithm. Operation1 follows Operation2")
        self.operation2()
        self.operation1()


class ConcreteClass(AbstractClass):
    def operation1(self):
        print("My Concrete Operation1")

    def operation2(self):
        print("Operation 2 remains same")

class Client:
    def main(self):
        self.concrete = ConcreteClass()
        self.concrete.template_method()


client = Client()
client.main()
```

## 4. 模板方法模式示例：旅行社
旅行社通常定义了各种旅游线路，并提供度假套装行程，一个行程套餐本质上是作为客户允诺的一次旅行，其中涉及到一些信息如游览地点、交通
方式等。同样的行程可以根据客户的需求进行不同的定制。定义旅行的AbstractClass接口（Trip类），包括多个抽象方法（setTransport()、
day1()、day2()、day3()、returnHome()）。模板方法itinerary()定义该旅行的行程。定义ConcreteClass帮助我们根据客户的需要对旅行进
行相应的定制。

代码如下：
```python
from abc import ABCMeta, abstractmethod, ABC
class Trip(metaclass=ABCMeta):
    @abstractmethod
    def setTransport(self):
        pass

    @abstractmethod
    def day1(self):
        pass

    @abstractmethod
    def day2(self):
        pass

    @abstractmethod
    def day3(self):
        pass

    @abstractmethod
    def returnHome(self):
        pass

    def itinerary(self):
        self.setTransport()
        self.day1()
        self.day2()
        self.day3()
        self.returnHome()


class VeniceTrip(Trip):
    def setTransport(self):
        print("Take a boat and find your way in the Grand Canal")

    def day1(self):
        print("Appreciate Doge's Palace")

    def day2(self):
        print("Enjoy the food near the Rialto Bridge")

    def day3(self):
        print("Get souvenirs for friends and get back")

    def returnHome(self):
        pass

class MaldivesTrip(Trip):
    def setTransport(self):
        print("On foot, on any island, Wow!")

    def day1(self):
        print("Enjoy the marine life of Banana Reef")

    def day2(self):
        print("Go for the water sports and snorkelling")

    def day3(self):
        print("Relax on the beach and enjoy the sun")

    def returnHome(self):
        print("Don't feel like leaving the beach..")

class TravelAgency:
    def arrange_trip(self):
        choice = input("What kind of place you'd like to go historical or a beach?")
        if choice == 'historical':
            self.trip = VeniceTrip()
            self.trip.itinerary()
        if choice == 'beach':
            self.trip = MaldivesTrip()
            self.trip.itinerary()


TravelAgency().arrange_trip()
```

## 5. 钩子
钩子是在抽象类中声明的方法，通常被赋予一个默认实现。钩子背后的思想是为子类提供按需钩取算法的能力。

但是并不强制子类使用钩子，可以忽略。例如在饮料的例子中，可以添加一个简单的钩子，看看调味品是否需要与茶或咖啡一起提供，具体视客户
的意愿而定。

## 6. 好莱坞原则
好莱坞原则是说不要给我们打电话，我们会打给你。允许低层组件使用好莱坞原则将自己挂入系统中，但是由高层组件确定低层系统的使用方式及
何时需要它们。

## 7. 模板方法模式的优缺点
优点：
- 没有代码重复。
- 由于模板方法模式使用继承而不是合成，因此能够对代码进行重用。
- 灵活性允许子类决定如何实现算法中的步骤。

缺点：
- 调试和理解模板方法模式中的流程序列有时会令人困惑。可能最终实现的方法是一个不应该实现的方法，或根本没有实现抽象方法。文档和严格
的错误处理必须由程序员完成。
- 模板框架的维护麻烦，因为任何层次的变更都可能对实现造成干扰。


## 后记
小结一下：
- 模板方法模式的定义。
- 如何使用模板方法模式封装算法，并通过覆盖子类的方法提供实现不同行为的灵活性。
- 钩子和好莱坞原则。
- 模板方法模式的优缺点。

下一章是MVC设计模式。
