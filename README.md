# FoodShield
FoodShield 是一个面向外卖平台订单通信场景的匿名订单认证与可审计通信系统，支持用户匿名身份、订单 Token 认证、骑手实时通信、管理员条件溯源和 Merkle 日志完整性验证。

## 核心特性
- 🕶️ **匿名身份保护**：用户注册后生成匿名 PID，通信过程中不直接暴露真实用户身份，保障用户的身份安全。
- 🔐 **订单认证机制**：基于 HMAC Token 验证用户是否为合法订单持有者。
- 💬 **实时订单通信**：用户端与骑手端基于 WebSocket 进行订单级实时聊天。
- 🧾 **消息持久化记录**：聊天消息写入 SQLite 数据库，并保存发送方、角色、时间戳和消息哈希。
- 🌲 **Merkle 日志审计**：基于消息哈希构建 Merkle Root，用于检测通信记录是否被篡改。
- 🧑‍💼 **管理员条件溯源**：管理员在审计场景下可根据 PID 查询真实用户映射。
- 🛡️ **篡改检测与定位**：消息内容被直接修改后，系统可检测哈希不一致并定位异常消息。

## 系统架构

### 1.前端展示层

前端展示层包括用户端、骑手端和管理员端三个网页界面：

- 用户端：负责用户注册、匿名 PID 获取、订单创建、Token 验证和订单通信；
- 骑手端：负责查看待接订单、接单和与用户进行订单级实时通信；
- 管理员端：负责管理员登录、订单查看、消息审计、完整性验证和条件溯源。

### 2.后端服务层

后端服务层基于 Flask 和 Flask-SocketIO 实现，是系统的核心业务处理中心，主要负责：

- 接收并处理用户端、骑手端和管理员端请求；
- 管理用户注册、订单创建、订单认证和骑手接单流程；
- 通过 WebSocket 实现用户与骑手之间的实时消息转发；
- 与数据库交互，完成用户、订单、消息和审计日志的读写操作。

### 3.安全审计层

安全审计层负责实现系统的核心安全机制，主要包括：

- 匿名身份管理模块：生成并维护用户匿名 PID；
- 订单认证模块：基于 HMAC-SHA256 生成和验证订单 Token；
- 消息哈希模块：为每条聊天消息生成消息哈希；
- Merkle Tree 日志审计模块：基于消息哈希生成 Merkle Root，并验证通信记录完整性；
- 管理员权限控制模块：限制后台审计接口只能由管理员访问；
- 条件溯源模块：在审计场景下根据 PID 查询真实用户映射关系。

### 4.数据持久层

数据持久层基于 SQLite 实现，用于保存系统运行过程中的核心数据，包括：

- 用户信息与 PID 映射关系；
- 订单信息、订单状态和订单 Token；
- 用户与骑手之间的聊天消息；
- 消息哈希、Merkle Root 和管理员审计日志。

## 技术栈
- 后端框架：Python,Flask,Flask-SocketIO
- 前端技术：HTML,CSS,JavaScript
- 数据库：SQLite
- 通信机制：WebSocket
- 安全机制：HMAC-SHA256,SHA-256,Merkle Tree,
- 测试环境：Windows, PowerShell, 浏览器

## 项目结构
```text
FoodShield/
├── project/
│   ├── crypto/
│   │   ├── auth_utils.py        # 管理员认证与权限相关工具
│   │   ├── merkle.py            # Merkle Tree 构建与完整性验证
│   │   ├── message_utils.py     # 消息哈希与消息处理工具
│   │   ├── pid.py               # 匿名 PID 生成逻辑
│   │   └── token_utils.py       # 订单 Token 生成与验证逻辑
│   │
│   ├── database/
│   │   ├── db.py                # 数据库初始化、查询与执行封装
│   │   └── schema.sql           # SQLite 数据库表结构定义
│   │
│   ├── frontend/
│   │   ├── css/
│   │   │   └── style.css        # 前端页面样式
│   │   ├── index.html           # 首页
│   │   ├── user.html            # 用户端页面
│   │   ├── rider.html           # 骑手端页面
│   │   └── admin.html           # 管理员端页面
│   │
│   ├── server/
│   │   ├── app.py               # Flask 主程序与核心路由
│   │   ├── auth.py              # 认证与权限控制逻辑
│   │   ├── logger.py            # 日志记录相关逻辑
│   │   └── security_audit.py    # 安全审计、完整性验证与溯源逻辑
│   │
│   └── integration_demo.py      # 集成演示脚本
│   
│
├── requirements.txt             # Python 依赖列表
├── README.md                    # 项目说明文档
└── .gitignore                   # Git 忽略配置
```

## 环境要求
- Python 3.10+
- pip（Python包管理工具，默认随Python安装）
- 推荐使用 Python 虚拟环境
- 现代浏览器： Chrome/Edge/Firefox
- 操作系统：Windows/MacOS/Linux

## 主要依赖
- Flask
- Flask-CORS
- Flask-SocketIO
- eventlet
- SQLite

## 快速开始
### 克隆项目
```
git clone https://github.com/hxhdhcjmet/FoodShield.git
cd FoodShield
```

### 创建并激活虚拟环境
```
Windows PowerShell：

python -m venv venv
.\venv\Scripts\Activate.ps1

macOS / Linux：

python3 -m venv venv
source venv/bin/activate
```

### 安装依赖
```
pip install -r requirements.txt
```

### 项目启动
在项目根目录执行：
```
python -m project.server.app
```

启动成功后，终端会显示类似信息：
```
Running on http://127.0.0.1:5000
```

注意：由于项目采用 project 作为顶层包，建议从项目根目录使用 python -m project.server.app 启动，不建议直接进入 project/server/ 后执行 python app.py。

## 页面入口
|页面|入口|
|---|---|
|首页|http://127.0.0.1:5000/|
|用户端|http://127.0.0.1:5000/user.html|
|骑手端|http://127.0.0.1:5000/rider.html|
|管理员端|http://127.0.0.1:5000/admin.html|

## 演示流程

## 核心安全机制

### 匿名 PID 机制

用户注册后，系统为用户生成匿名身份标识 PID。日常订单通信过程中，系统主要使用 PID 表示用户身份，而不是直接暴露真实用户信息。

### HMAC Token 订单认证

用户创建订单后，系统基于订单号、匿名 PID 和时间戳生成订单 Token。用户进入订单通信前需要提交相关认证信息，服务器验证通过后才允许进入对应通信通道。

### WebSocket 实时通信

系统基于 WebSocket 实现用户端与骑手端之间的订单级实时通信。用户和骑手围绕同一个 order_id 加入通信房间，实现双向消息收发。

### 消息哈希与持久化

每条聊天消息都会写入 SQLite 数据库，并保存消息内容、发送方身份、角色、时间戳和消息哈希。消息哈希用于后续完整性验证。

### Merkle Tree 日志审计

系统将订单下的消息哈希组织为 Merkle Tree，并生成 Merkle Root。管理员可以基于 Merkle Root 验证通信记录是否被篡改。

### 管理员权限控制

后台审计接口需要管理员登录后才能访问。未登录用户访问后台消息接口会被拒绝，错误密码无法建立管理员会话。

### 条件溯源机制

日常通信中系统只使用 PID。发生投诉、恶意行为或审计需求时，管理员可以根据 PID 查询真实用户映射关系，实现条件溯源。

## 测试说明

## 已知限制

## 后续优化方向