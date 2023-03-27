---
layout:     post
title:      设计模式（八）MCV模式
subtitle:   根据《Python设计模式（第2版）》一书的学习，记录下来的笔记。本篇博客是MCV模式，是一种复合模式，把一些设计模式组合起来使用。
date:       2020-03-18
author:     K4ys0n
header-img: img/post-bg-coffee.jpeg
catalog:    true
tags:
    - 设计模式
    - Python
    - 笔记
---

## 前言
通常设计模式不是单独使用的，需要同时使用并加以组合，以实现特定的设计解决方案。

复合模式将两个或更多模式组合成解决常见或普遍性问题的解决方案。复合模式不是同时使用的一组模式，而是一个问题的通用解决方案。

MCV模式就是一种复合模式。

## 1. MCV模式的基本部分
MCV模式，即模型-视图-控制器模式，包含三个基本部分：模型、视图、控制器。

模型提供数据和业务逻辑（如何存储和查询信息），视图负责数据的展示（如何呈现），控制器是两者之间的粘合剂，根据用户要求的呈现方式来
协调模型和视图。**视图和控制器依赖于模型**。

- 模型：声明一个存储和操作数据的类。定义针对数据的所有操作（创建、修改、删除等），并提供与数据使用方式有关的方法。
- 视图：声明一个类来构建用户界面和显示数据。提供相应的方法，帮助我们根据上下文和应用程序的需要来构建Web或GUI界面。
- 控制器：声明一个连接模型和视图的类。从请求接收数据，并将其发送到系统的其他部分。它需要提供用于路由请求的方法。
- 客户端：声明一个类，根据某些操作来获得某些结果。

## 2. MCV模式常用情况
- 当需要更改展示方式而不更改业务逻辑时。
- 多个控制器可用于使用多个视图来更改用户界面上的展示。
- 再次重申，当模型改变时，视图无需改动，因为它们是相互独立的。

## 3. MCV模式的主要意图
- 将数据和数据的展示隔离开来。
- 使类的维护和实现更加简单。
- 灵活地改变数据的存储和显示方式。

## 4. MCV模式各部分应注意
- 模型：模型会提供状态以及改变状态的方法，但它不知道数据是如何展示给客户端的。模型必须在多个操作中保持一致，否则客户端可能会损坏
或展示过时的数据，这是不可容忍的。
- 视图：视图可以独立开发，但不应包含任何复杂的逻辑，因为逻辑应该放在控制器或模型中。视图应足够灵活，适应多种平台。避免与数据库直
接交互，而是依靠模型来获取所需的数据。
- 控制器：控制器将数据传递给视图，以便将信息呈现在接口上，供用户查看。控制器不应该进行数据库调用或参与数据的展示，应该作为模型和
视图之间的粘合剂，并且要尽可能地薄。

举个例子：假设开发一个应用程序，告诉用户云公司所提供的营销服务，包括电子邮件、短信和语音设施。那么定义model类（模型）、view类
（视图）和Controller类（控制器），Client类将实例化控制器，然后控制器对象就会根据客户端的请求来调用适当的方法。
```python
class Model(object):
    services = {
        'email': {'number': 1000, 'price': 2, },
        'sms': {'number': 1000, 'price': 10, },
        'voice': {'number': 1000, 'price': 15, },
    }

class View(object):
    def list_services(self, services):
        for svc in services:
            print(svc, ' ')

    def list_pricing(self, services):
        for svc in services:
            print("For", Model.services[svc]['number'], svc, "message you pay $", Model.services[svc]['price'])

class Controller(object):
    def __init__(self):
        self.model = Model()
        self.view = View()

    def get_services(self):
        services = self.model.services.keys()
        return self.view.list_services(services)

    def get_pricing(self):
        services = self.model.services.keys()
        return self.view.list_pricing(services)

class Client(object):
    controller = Controller()
    print("Services Provided:")
    controller.get_services()
    print("Pricing for Services:")
    controller.get_pricing()
```

## 5. MVC模式实例：Tornado Web应用程序
web应用程序利用Tornado框架和SQLite3数据库，包含以下几个部分：
- IndexHandler：返回存储在数据库中的所有任务，它返回一个与关键任务有关的字典，执行SELECT数据库操作来获取这些任务。
- NewHandler：添加新任务。它检查食肉有一个POST调用来创建一个新任务，并在数据库中执行INSERT操作。
- UpdateHandler：将任务标记为完成或重新打开给定任务。将执行UPDATE数据库操作，将任务的状态设置为open/closed。
- DeleteHandler：将从数据库中删除指定的任务。一旦删除，任务将会从任务列表中消失。
- _execute()方法：以SQL查询作为输入并执行所需的数据库操作：创建DB连接、获取游标对象、使用游标对象执行事务、提交查询、关闭连接。

Tornado框架中的视图，包括三个模板：
- index.html：用于列出所有任务的模板。
- new.html：用于创建新任务的视图。
- base.html：其他模板要继承的基本模板。

控制器，也就是应用程序路由
- /：用于列出所有任务的路由。
- /todo/new：创建新任务的路由。
- /todo/update：将任务状态更新为打开或关闭的路由。
- /todo/delete：删除已完成任务的路由。

提前安装tornado、sqlite库，然后编写代码如下：
```python
import tornado
import tornado.web
import tornado.ioloop
import tornado.httpserver
import sqlite3

class IndexHandler(tornado.web.RequestHandler):
    def get(self):
        query = "select * from task"
        todos = _execute(query)
        self.render('index.html', todos=todos)

class NewHandler(tornado.web.RequestHandler):
    def post(self):
        name = self.get_argument('name', None)
        query = "create table if not exists task (id INTEGER PRIMARY KEY, name TEXT, status NUMERIC)"
        _execute(query)
        query = "insert into task (name, status) values ('%s', %d) " % (name, 1)
        _execute(query)
        self.redirect('/')

    def get(self):
        self.render('new.html')

class UpdateHandler(tornado.web.RequestHandler):
    def get(self, id, status):
        query = "update task set status=%d where id=%s" % (int(status), id)
        _execute(query)
        self.redirect('/')

class DeleteHandler(tornado.web.RequestHandler):
    def get(self, id):
        query = "delete from task where id=%s" % id
        _execute(query)
        self.redirect('/')

class RunApp(tornado.web.Application):
    def __init__(self):
        Handlers = [
            (r'/', IndexHandler),
            (r'/todo/new', NewHandler),
            (r'/todo/update/(\d+)/(\d+)', UpdateHandler),
            (r'/todo/delete/(\d+)', DeleteHandler),
        ]
        settings = dict(
            debug=True,
            template_path='templates',
            static_path="static",
        )
        tornado.web.Application.__init__(self, Handlers, **settings)


conn = sqlite3.connect('db.sqlite3')

def _execute(query):
    c = conn.cursor()
    tt = c.execute(query)
    conn.commit()
    todos = []
    for t in tt:
        todos.append(t)
    return todos


if __name__ == "__main__":
    http_server = tornado.httpserver.HTTPServer(RunApp())
    http_server.listen(5000)
    tornado.ioloop.IOLoop.instance().start()
    conn.close()
```

注意：要在MVCPattern.py所在目录下创建templates目录，在templates中创建base.html、new.html、index.html。运行MVCPattern.py后，
在浏览器输入http://localhost:5000/todo/new来添加几个选项，第一次一定要先从这个链接进去，才会创建db.sqlite3数据库文件，不然不会自动创建数据库会报错。

## MVC模式的优点
- MVC分为三个主要部分，这有助于提高可维护性，强制松耦合，并降低复杂性。
- MVC允许对前端进行独立更改，而对后端逻辑无需任何修改或只需进行很少的更改，因此开发工作仍可以独立运行。
- 可以更改模型或业务逻辑，而无需对视图进行任何更改。
- 可以更改控制器，而不会对视图或模型造成任何影响。
- 有助于招聘具有特定能力的人员，如平台工程师和UI工程师，他们可以在自己专业领域独立工作。

## 后记
小结一下：
- 了解了MVC模式的架构：模型-视图-控制器。
- 如何使用MVC模式来确保松散耦合，并维护一个用于独立任务开发的多层框架。
- MVC模式的优点。

下一章是状态设计模式。
