---
layout:     post
title:      设计模式（二）工厂模式
subtitle:   根据《Python设计模式（第2版）》一书的学习，记录下来的笔记。本篇博客是工厂模式，是一种创建型模式。
date:       2020-01-07
author:     K4ys0n
header-img: img/post-bg-coffee.jpeg
catalog:    true
tags:
    - 设计模式
    - Python
    - 笔记
---

## 前言
感觉工厂模式比起单例模式要复杂一些，得花点时间理解才行，本章主要包含了三个部分：简单工厂
模式、工厂方法模式和抽象工厂模式。在最后会做一下简单的对比。

此外，本章python代码实现时，都会把提炼抽象类和抽象方法，这样逻辑会更加统一。

本章源码链接：[https://github.com/K4ys0n/design-pattern/blob/master/factoryPattern.py](https://github.com/K4ys0n/design-pattern/blob/master/factoryPattern.py)

## 工厂模式
#### 1. 工厂模式简介
所谓“工厂”就是一个**负责创建其他类型对象的类**。

客户端输入或者设置某些参数，让这个“工厂”产生客户所需要的产品，返回给客户端。

那么问题来了，客户端是可以直接创建对象，也就是说它可以直接选择自己生产产品，为什么还需要
一个工厂呢？

原因如下：
- **松耦合，对象的创建可以独立于类的实现**（类的实现都隐藏在工厂背后的接口中，我们只需要
修改参数让工厂输出某个类的对象即可）。
- 客户端无需了解创建对象的类，但是照样可以使用它来创建对象，只需要修改参数、方法等即可，
这样就**简化了客户端的实现**。
- 可以轻松地在工厂中**添加其他类来创建其他类型的对象，无需修改客户端代码**。客户端只需要
传递另一个参数即可。
- 工厂还可以重用现有对象。但是，如果客户端直接创建对象的话，总是创建一个新对象。

举个例子：

讨论一个制造玩具车或玩偶的公司，假设公司里有一台制造玩具车的机器，领导后来想用它来造玩偶。
这时按照工厂模式就是，机器是接口，领导是客户端，领导只关心制造的对象（玩具）和创建对象的
接口（机器）。

#### 2. 三种工厂模式对比
简单工厂模式|工厂方法模式|抽象工厂模式
---|---|---
允许接口创建对象，但不会暴露对象的创建逻辑。|允许接口创建对象，但使用哪个类来创建对象，则是交由子类决定的。|一个能创建一系列相关的对象而无需指定/公开其具体类的接口，该模式能够提供其他工厂的对象，在其内部创建其他对象。

#### 3. 简单工厂模式
想象一下森林里，有动物，有猫有狗，猫和狗都有叫声，我们现在只要输入一个参数：猫，森林工厂就输出猫叫；狗，森林工厂就输出狗叫。

也就是，森林是工厂，动物的叫声是产品，我们可以把动物设置成类，动物这个类有一个输出叫声的接口，而猫和狗继承自动物这个类；
接着森林工厂可以调用这些接口，只需要我们控制好参数，比如输入参数：猫或者狗。

```python
from abc import ABCMeta, abstractmethod


class Animal(metaclass=ABCMeta):
    @abstractmethod
    def do_say(self):
        pass


class Dog(Animal):
    def do_say(self):
        print("Bhow Bhow!!")


class Cat(Animal):
    def do_say(self):
        print("Meow Meow!!")


# forest factory defined
class ForestFactory(object):
    def make_sound(self, object_type):
        return eval(object_type)().do_say()


# client code
if __name__ == '__main__':
    ff = ForestFactory()
    animal = input("Which animal should make sound Dog or Cat?")
    ff.make_sound(animal)

```

#### 4. 工厂方法模式
工厂方法模式与简单工厂模式最直接的区别就是，不直接创建对象，而是定义了一个接口，让子类来完成。

工厂方法使设计更加具有可定制性。它可以返回相同的实例或子类，而不是某种类型的对象。

举个例子：假设我们想在不同类型的社交网络（LinkedIn、Facebook）建立个人简介，在LinkedIn上有
关于个人申请的专利或作品的区，在Facebook上有显示度假地点的照片区。此外，两者都有个人信息区。

那么我们就可以先抽象一个类作为通用产品类，并提供一个产品接口，用来定义我们的区，然后写各种
子类来实现不同的接口。

接着创建一个抽象工厂类，里面提供了一个生产产品的方法，这个方法通过子类继承来实现，子类会根
据不同参数调用不同接口来生产不同产品。
```python
from abc import ABCMeta, abstractmethod


class Section(metaclass=ABCMeta):
    @abstractmethod
    def describe(self):
        pass


class PersonalSection(Section):
    def describe(self):
        print("Personal Section")


class AlbumSection(Section):
    def describe(self):
        print("Album Section")


class PatentSection(Section):
    def describe(self):
        print("Patent Section")


class PublicationSection(Section):
    def describe(self):
        print("Publication Section")


class Profile(metaclass=ABCMeta):
    def __init__(self):
        self.sections = []
        self.createProfile()

    @abstractmethod
    def createProfile(self):
        pass

    def getSections(self):
        return self.sections

    def addSections(self, section):
        self.sections.append(section)


class linkedin(Profile):
    def createProfile(self):
        self.addSections(PersonalSection())
        self.addSections(PatentSection())
        self.addSections(PublicationSection())


class facebook(Profile):
    def createProfile(self):
        self.addSections(PersonalSection())
        self.addSections(AlbumSection())


if __name__ == '__main__':
    profile_type = input("Which Profile you'd like to create?[LinkedIn or Facebook]")
    profile = eval(profile_type.lower())()
    print("Creating Profile..", type(profile).__name__)
    print("Profile has sections --", profile.getSections())
```
上述代码中，我们首先创建了Section抽象类，描述产品接口，也就是通用区，接着通过继承Section类，
写了PersonalSection等几个不同的接口类，并提供了接口方法describe，当然具体功能没有实现，只是
随便打印了点东西。

然后建立工厂抽象类Profile，并提供初始化方法和createProfile生产产品方法，以及addSection添加
接口和getSections获取接口已添加接口的方法。通过继承这个类，我们编写了linkedin和facebook两个
子类，我们输入参数linkedin或者facebook来实例化这两个子类即可生成我们需要的产品：带有不同区域
的linkedin页面和facebook页面。

而添加接口的过程我们已经写在工厂抽象类的初始化中了，所以所有子类工厂都会在实例化的时候直接初
始化相关接口来实例化。不过我们可以在子类的实现中去决定需要添加哪些接口（createProfile方法）。

这样一来，**客户端完全不需要关心内部要传递哪些参数以及需要实例化哪些类。由于添加新类更加容
易，所以降低了维护成本**。

#### 5. 抽象工厂模式
抽象工厂模式的主要是提供一个接口来创建一系列相关对象，而无需指定具体的类。

工厂方法将创建实例的任务交给子类，抽象工厂方法则是创建一系列相关子类，这些子类调用不同接口实
现不同的功能。

抽象工厂模式不仅确保客户端与对象的创建相互隔离，同时还确保客户端能够使用创建的对象。但客户端
只能通过工厂接口访问对象，抽象工厂模式能帮助客户端一次使用来自一个产品/系列的多个对象。

举个例子：披萨店生产多种披萨饼，有**美式披萨**和**印式披萨饼**，那么我们可以抽象一个**披萨工厂**
类PizzaFactory，并且提供两个方法来生产**素菜披萨**和**非素菜披萨**（createVegPizza和createNonVegPizza），
然后创造两个具体工厂IndianPizzaFactory和USPizzaFactory，继承了抽象工厂的方法。

工厂类型|披萨类型|披萨名称
---|---|---
美式披萨|素菜披萨|墨西哥披萨
美式披萨|非素菜披萨|汉姆披萨（基于素菜披萨：墨西哥披萨）
印式披萨|素菜披萨|多彩披萨
印式披萨|非素菜披萨|鸡肉披萨（基于素菜披萨：多彩披萨）

关于披萨要抽象两个基类：素菜披萨VegPizza和非素菜披萨NonVegPizza。素菜披萨类有一个prepare方
法（准备素菜），非素菜披萨类有一个serve方法（添加肉类）。根据这两个基类继承出了墨西哥披萨等
四种不同口味的披萨。

客户端我们定义一个类，提供接口供顾客访问，让他们说明他们的需求。比如说我想要一种美式非素菜披
萨，那么客户端访问工厂USPizzaFactory，工厂会调用汉姆披萨类HamPizza所提供的接
口createNonVegPizza方法来制作披萨。 而汉姆披萨类是继承自素菜披萨类VegPizza的，同理其他也是
这样的工作思路。
```python
from abc import ABCMeta, abstractmethod


class PizzaFactory(metaclass=ABCMeta):      # 抽象披萨工厂类
    @abstractmethod
    def createVegPizza(self):
        pass

    @abstractmethod
    def createNonVegPizza(self):
        pass


class IndiaPizzaFactory(PizzaFactory):      # 印式披萨工厂类
    def createVegPizza(self):
        return DeluxVeggiePizza()

    def createNonVegPizza(self):
        return ChickenPizza()


class USPizzaFactory(PizzaFactory):     # 美式披萨工厂类
    def createVegPizza(self):
        return MexicanVegPizza()

    def createNonVegPizza(self):
        return HamPizza()


class VegPizza(metaclass=ABCMeta):      # 抽象素菜披萨类
    @abstractmethod
    def prepare(self, VegPizza):
        pass


class NonVegPizza(metaclass=ABCMeta):   # 抽象非素菜披萨类
    @abstractmethod
    def serve(self, VegPizza):
        pass


class DeluxVeggiePizza(VegPizza):       # 多彩披萨类
    def prepare(self):
        print("Prepare ", type(self).__name__)


class ChickenPizza(NonVegPizza):    # 鸡肉披萨类
    def serve(self, VegPizza):
        print(type(self).__name__, "is served with Chicken on ", type(VegPizza).__name__)


class MexicanVegPizza(VegPizza):    # 墨西哥披萨类
    def prepare(self):
        print("Prepare ", type(self).__name__)


class HamPizza(NonVegPizza):        # 汉姆披萨类
    def serve(self, VegPizza):
        print(type(self).__name__, "is served with Ham on ", type(VegPizza).__name__)


class PizzaStore:           # 披萨店，即客户端 
    def __init__(self):
        pass

    def makePizzas(self):   # 制作披萨，根据需求实例化工厂，选择调用工厂的接口制作素菜或者非素菜披萨
        for factory in [IndiaPizzaFactory(), USPizzaFactory()]:
            self.factory = factory
            self.NonVegPizza = self.factory.createNonVegPizza()
            self.VegPizza = self.factory.createVegPizza()
            self.VegPizza.prepare()
            self.NonVegPizza.serve(self.VegPizza)


pizza = PizzaStore()    # 实例化客户端
pizza.makePizzas()
```
如上可以看到工厂类，它们带有创建披萨对象的方法，这些方法返回披萨对象。

而披萨对象是两种素菜类和两种非素菜类实例化而来的。

现在客户四种披萨各要一份，那么客户端就依次调用两个工厂，让每个工厂都制作一个素菜类披萨和非
素菜类披萨，这样就可以四种披萨都做好了。

#### 6. 工厂方法和抽象工厂方法的对比
工厂方法|抽象工厂方法
---|---
向客户开放了一个创建对象的方法|包含一个或多个工厂方法来创建一个系列的相关对象
使用继承和子类来决定要创建哪个对象|使用组合将创建对象的任务委托给其他类
用于创建一个产品|用于创建相关产品的系列

## 后记
小结一下：
- **简单工厂模式**：可以在运行时根据客户端传入的参数类型来创建相应的实例（**森林猫狗叫**，用客户端
类方法传入类名作为参数）。
- **工厂方法模式**：简单工厂的一个变体，定义了一个抽象接口，子类继承这个接口完成产品对象的创建
成（**不同平台不同信息区**，抽象类派生出子类，在子类中实现产品对象的创建，客户端只要选择实例化
哪个子类即可，因为接口调用是设置好在类的初始化中了）。
- **抽象工厂方法**：提供了一个接口，无需指定具体的类就能创建一系列的相关对象（**印式美式披萨**，
实例化工厂美式披萨工厂，调用生产方法创建某个类型的披萨，也可以整个系列的美式披萨都产生）。

下一章是门面模式。

源码链接：[https://github.com/K4ys0n/design-pattern/blob/master/factoryPattern.py](https://github.com/K4ys0n/design-pattern/blob/master/factoryPattern.py)