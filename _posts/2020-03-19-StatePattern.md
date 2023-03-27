---
layout:     post
title:      设计模式（九）状态设计模式
subtitle:   根据《Python设计模式（第2版）》一书的学习，记录下来的笔记。本篇博客是状态设计模式，是一种行为型模式。
date:       2020-03-19
author:     K4ys0n
header-img: img/post-bg-coffee.jpeg
catalog:    true
tags:
    - 设计模式
    - Python
    - 笔记
---

## 前言
行为模式关注的是对象的响应性，它们通过对象之间的交互以实现更强大的功能。
状态设计模式也是一种行为模式。

## 1. 状态设计模式的定义
在状态模式中，一个对象可以基于其内部状态封装多个行为，可以看作是在运行改变对象行为的一种方式。

举个例子：收音机具有AM/FM两种调频方式和一个扫描按钮，该按钮可以扫描多个FM/AM频道。它的基本状态已经设定好了，如设为FM，这个时候单
击扫描按钮可以将收音机调谐到多个有效的FM频率或频道。当状态改为AM时，扫描按钮则会帮助用户调谐到多个AM频道。根据AM、FM两种状态来相
应地改变状态。

## 2. 状态设计模式的组成部分
- State：被认为是封装对象行为的接口，这个行为与对象的状态相关联。
- ConcreteState：实现State接口的子类，实现与对象的特定状态相关联的实际行为。
- Context：定义了客户感兴趣的接口，维护一个ConcreteState子类的实例，该子类在内部定义了对象的特定状态的实现。

简单代码表示如下，其中Handle()抽象方法为状态接口：
```python
from abc import abstractmethod, ABCMeta
class State(metaclass=ABCMeta):
    @abstractmethod
    def Handle(self):
        pass

class ConcreteStateB(State):
    def Handle(self):
        print("ConcreteStateB")

class ConcreteStateA(State):
    def Handle(self):
        print("ConcreteStateA")

class Context(State):
    def __init__(self):
        self.state = None

    def getState(self):
        return self.state

    def setState(self, state):
        self.state = state

    def Handle(self):
        self.state.Handle()


context = Context()
stateA = ConcreteStateA()
stateB = ConcreteStateB()

context.setState(stateA)
context.Handle()
context.setState(stateB)
context.Handle()
```

## 3. 状态设计模式实例：电视机开关
直接上代码了，其实与上述简单代码类似：
```python
from abc import abstractmethod, ABCMeta
class State(metaclass=ABCMeta):
    @abstractmethod
    def doThis(self):
        pass

class StartState(State):
    def doThis(self):
        print("TV Switching ON..")

class StopState(State):
    def doThis(self):
        print("TV Switching OFF..")

class TVContext(State):
    def __init__(self):
        self.state = None

    def getState(self):
        return self.state

    def setState(self, state):
        self.state = state

    def doThis(self):
        self.state.doThis()


context = TVContext()
context.getState()

start = StartState()
stop = StopState()

context.setState(stop)
context.doThis()
```

## 4. 状态设计模式实例：计算机系统开关机、休眠和挂起
首先是定义计算机状态类ComputerState接口，包含属性name和allowed，name表示对象的状态，allowed表示允许进入的状态的对象的列表。
然后还要包含一个switch()方法，来实际改变对象的状态，其中用到\_\_class\_\_可以实现对类的引用，如
self.\_\_class\_\_.\_\_name\_\_可以调用类的名称。

接着是四种ConcreteState类，实现State接口，即：
- On：打开计算机，允许Off、Suspend和Hibernate状态。
- Off：关闭计算机，允许On状态。
- Hibernate：休眠模式，允许On状态。
- Suspend：挂起模式，允许On状态。

最后实现Context类，也就是计算机，一个是初始化方法，定义计算机的基本状态，另一个是change()方法，用来改变对象的状态，但是实际上是
调用了ConcreteState类实现的。

具体代码如下：
```python
class ComputerState(object):
    name = "state"
    allowed = []

    def switch(self, state):
        if state.name in self.allowed:
            print('Current:', self, '=> switched to new state', state.name)
            self.__class__ = state
        else:
            print('Current:', self, '=> switching to', state.name, 'not possible.')

    def __str__(self):
        return self.name

class Off(ComputerState):
    name = "off"
    allowed = ['on']

class On(ComputerState):
    name = "on"
    allowed = ['off', 'suspend', 'hibernate']

class Suspend(ComputerState):
    name = "suspend"
    allowed = ['on']

class Hibernate(ComputerState):
    name = "hibernate"
    allowed = ['on']

class Computer(object):
    def __init__(self, model='HP'):
        self.model = model
        self.state = Off()

    def change(self, state):
        self.state.switch(state)


if __name__ == "__main__":
    comp = Computer()
    # State on
    comp.change(On)
    # Switch off
    comp.change(Off)
    # Switch on again
    comp.change(On)
    # Suspend
    comp.change(Suspend)
    # Try to hibernate - cannot!
    comp.change(Hibernate)
    # switch on back
    comp.change(On)
    # Finally off
    comp.change(Off)
```
执行了上述代码会有如下结果：
```shell script
Current: off => switched to new state on
Current: on => switched to new state off
Current: off => switched to new state on
Current: on => switched to new state suspend
Current: suspend => switching to hibernate not possible.
Current: suspend => switched to new state on
Current: on => switched to new state off
```

## 5. 状态设计模式的优缺点
优点：
- 对象的行为是其状态的函数结果，并且行为在运行时根据状态而改变，这可以消除对if-else或switch-case条件逻辑的依赖。
- 使用状态模式，更易于添加状态来支持额外的行为。
- 状态设计模式提高了聚合性，因为特定于状态的行为被聚合到ConcreteState类中，并且放置在代码中的同一个地方。
- 通过只添加一个ConcreteState类来添加行为是非常容易的，因此状态模式盖上了扩展应用程序行为时的灵活性，而且全面提高了代码的可维护
性。

不足：
- 类爆炸：可能导致创建了太多功能较为单一的类，增加了代码量，又使得状态结构更加难以审查。
- 随着每个新行为的引入，Context类都需要进行相应的更新以处理每个行为，使得上下文行为更容易受到每个新的行为的影响。

## 后记
小结一下：
- 对象的行为是根据它的状态来决定的，在运行时改变对象。
- Context类为客户端提供了一个更加简单的接口，同时ConcreteState能够让向对象添加行为变得更加容易。
- 状态设计模式提高了内聚性，易于扩展，还能清除冗余代码块，但同时也有缺陷，可能代码的数量会增加。

下一章是反模式。
