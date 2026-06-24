# FoodShield
FoodShield 是一个面向外卖平台订单通信场景的匿名订单认证与可审计通信系统。系统支持匿名 PID 身份、HMAC-SM3 订单 Token 认证、SM4-CBC 消息加密存储、WebSocket 实时通信、管理员条件溯源和基于 SM3 的 Merkle 日志完整性验证。

## 核心特性
- 🕶️ **匿名身份保护**：用户注册后生成匿名 PID，通信过程中不直接暴露真实用户身份，保障用户的身份安全。
- 🔐 **订单认证机制**：基于 HMAC Token 验证用户是否为合法订单持有者。
- 🔒 **消息加密存储**：聊天消息在写入数据库前使用 SM4-CBC 加密，查询展示时由服务端解密。
- 💬 **实时订单通信**：用户端与骑手端基于 WebSocket 进行订单级实时聊天。
- 🧾 **消息持久化记录**：聊天消息写入 SQLite 数据库，并保存发送方、角色、时间戳和基于 SM3 的 SM4-CBC 消息内容加密存储 日志审计。
- 🌲 **Merkle 日志审计**：基于 SM3 消息哈希构建 Merkle Root，用于检测通信记录是否被篡改。
- 🧑‍💼 **管理员条件溯源**：管理员在审计场景下可根据 PID 查询真实用户映射。
- 🛡️ **篡改检测与定位**：数据库中的消息密文被修改后，系统可检测哈希不一致并定位异常消息。

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

- 匿名身份管理模块：基于 HMAC-SM3 生成并维护用户匿名 PID；
- 订单认证模块：基于 HMAC-SM3 生成和验证订单 Token；
- 消息加密存储模块：使用 SM4-CBC 对聊天消息内容进行加密存储；
- 消息哈希模块：基于 SM3 为每条聊天消息生成消息哈希；
- Merkle Tree 日志审计模块：基于 SM3 消息哈希生成 Merkle Root，并验证通信记录完整性；
- 管理员权限控制模块：限制后台审计接口只能由管理员访问；
- 条件溯源模块：在审计场景下根据 PID 查询真实用户映射关系。

### 4.数据持久层

数据持久层基于 SQLite 实现，用于保存系统运行过程中的核心数据，包括：

- 用户信息与 PID 映射关系；
- 订单信息、订单状态和订单 Token；
- 用户与骑手之间的聊天消息密文；
- SM3 消息哈希、Merkle Root 和管理员审计日志。

## 技术栈
- 后端框架：Python,Flask,Flask-SocketIO
- 前端技术：HTML,CSS,JavaScript
- 数据库：SQLite
- 通信机制：WebSocket
- 安全机制：HMAC-SM3,SM3,SM4-CBC,Merkle Tree
- 国密算法依赖：gmssl
- 测试环境：Windows, PowerShell, 浏览器

## 项目结构
```text
FoodShield/
├── project/
│   ├── crypto/
│   │   ├── auth_utils.py        # HMAC-SM3 签名与验证工具
│   │   ├── merkle.py            # Merkle Tree 构建与完整性验证
│   │   ├── message_utils.py     # SM3 消息哈希与消息处理工具
│   │   ├── pid.py               # 匿名 PID 生成逻辑
│   │   ├── sm_utils.py          # SM3、HMAC-SM3、SM4-CBC 国密算法工具
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
├── pyproject.toml               # uv 项目配置文件
├── uv.lock                      # uv 依赖锁文件
├── README.md                    # 项目说明文档
└── .gitignore                   # Git 忽略配置
```

## 环境要求
- Python 3.10+
- pip（Python 包管理工具，默认随 Python 安装）
- 推荐使用 Python 虚拟环境
- 现代浏览器：Chrome/Edge/Firefox
- 操作系统：Windows/MacOS/Linux

> 💡 **提示**：本项目同时支持 pip 和 [uv](https://docs.astral.sh/uv/) 两种依赖管理方式，任选其一即可。

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

---

### 🚀 方式二：使用 uv（推荐）

`uv` 是一个极速的 Python 包管理器，可以替代 pip + venv 的手动流程，**一步完成**环境创建和依赖安装。

#### 安装 uv
```
Windows PowerShell：
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"

macOS / Linux：
curl -LsSf https://astral.sh/uv/install.sh | sh
```

#### 一键创建环境并安装依赖
```
uv sync
```
该命令会自动完成：
- 读取 `.python-version` 锁定 Python 版本
- 创建 `.venv` 虚拟环境
- 安装 `pyproject.toml` 中声明的全部依赖
- 生成 `uv.lock` 锁文件确保可复现构建

#### 启动项目
```
uv run python -m project.server.app
```
`uv run` 会自动使用 `.venv` 中的 Python 环境，无需手动激活虚拟环境。

> ⚡ 如果仍习惯 pip 工作流，`uv` 也兼容传统命令：
> ```bash
> uv pip install -r requirements.txt   # 等价于 pip install -r requirements.txt（但更快）
> ```

---

## 页面入口
|页面|入口|
|---|---|
|首页|http://127.0.0.1:5000/|
|用户端|http://127.0.0.1:5000/user.html|
|骑手端|http://127.0.0.1:5000/rider.html|
|管理员端|http://127.0.0.1:5000/admin.html|

## 演示流程
- 1.打开用户端页面，注册测试用户，系统生成匿名 PID。
- 2.用户创建订单，系统返回 order_id、timestamp 和 token。
- 3.用户提交订单信息并完成 Token 验证。
- 4.打开骑手端页面，刷新待接订单列表。
- 5.骑手接单后进入订单通信页面。
- 6.用户端与骑手端进行双向实时通信。
- 7.聊天消息写入数据库前使用 SM4-CBC 加密，并生成 SM3 消息哈希。
- 8.打开管理员端页面，登录管理员账号。
- 9.管理员查看订单消息与审计日志。
- 10.管理员生成 Merkle 快照并执行完整性验证。
- 11.修改数据库中的消息内容后再次验证，系统返回 VERIFY_FAIL 并定位异常消息。
- 12.管理员根据 PID 执行条件溯源。

## 核心安全机制

### 匿名 PID 机制

用户注册后，系统为用户生成匿名身份标识 PID。日常订单通信过程中，系统主要使用 PID 表示用户身份，而不是直接暴露真实用户信息。

### HMAC Token 订单认证

用户创建订单后，系统基于订单号、匿名 PID 和时间戳生成订单 Token。用户进入订单通信前需要提交相关认证信息，服务器验证通过后才允许进入对应通信通道。

### WebSocket 实时通信

系统基于 WebSocket 实现用户端与骑手端之间的订单级实时通信。用户和骑手围绕同一个 order_id 加入通信房间，实现双向消息收发。

### 基于 SM3 的 SM4-CBC 消息内容加密存储 日志审计与持久化

每条聊天消息都会写入 SQLite 数据库，并保存消息内容、发送方身份、角色、时间戳和基于 SM3 的 SM4-CBC 消息内容加密存储 日志审计。基于 SM3 的 SM4-CBC 消息内容加密存储 日志审计用于后续完整性验证。

### SM4-CBC 消息内容加密存储 日志审计

系统将订单下的基于 SM3 的 SM4-CBC 消息内容加密存储 日志审计组织为 SM4-CBC 消息内容加密存储，并生成 Merkle Root。管理员可以基于 Merkle Root 验证通信记录是否被篡改。

### 管理员权限控制

后台审计接口需要管理员登录后才能访问。未登录用户访问后台消息接口会被拒绝，错误密码无法建立管理员会话。

### 条件溯源机制

日常通信中系统只使用 PID。发生投诉、恶意行为或审计需求时，管理员可以根据 PID 查询真实用户映射关系，实现条件溯源。

## 测试说明
- 页面访问测试；
- 用户注册与 PID 生成测试；
- 订单创建与 Token 生成测试；
- 正确 Token 验证测试；
- 伪造 Token 拒绝测试；
- 骑手接单测试；
- 重复接单拦截测试；
- 用户与骑手双向通信测试；
- 消息历史持久化测试；
- 管理员登录与权限控制测试；
- Merkle 快照生成测试；
- 未篡改状态完整性验证测试；
- 数据库消息篡改检测测试；
- 条件溯源测试。

## 已知限制

- 当前系统为竞赛原型，主要用于本地演示和功能验证。
- 当前默认运行在 http://127.0.0.1:5000，生产部署时应启用 HTTPS/WSS。
- SQLite 数据库适合原型验证，生产环境可替换为 MySQL 或 PostgreSQL。
- 当前骑手身份为演示级设计，后续可扩展骑手注册、认证和权限管理。
- 管理员权限控制为基础实现，后续可加入多角色权限、操作审批和审计留痕增强机制。
- 当前 PID 映射由平台侧保存，后续可进一步研究更强匿名机制，例如盲签名或零知识证明。

## 后续优化方向
- 接入 HTTPS/WSS，增强传输安全；
- 增加骑手端身份认证与权限管理；
- 增加管理员多级权限与操作审批；
- 支持多订单、多用户并发测试；
- 优化前端交互和可视化展示；
- 引入更强的匿名认证机制；
- 将审计日志扩展为远程可信存证或链上存证。