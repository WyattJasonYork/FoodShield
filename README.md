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
系统主要由四方面构成：
1.用户端/骑手端网页界面：网页界面负责与用户进行交互；
2.平台服务器：负责处理用户请求，与数据库交互；
3.审计日志系统：负责记录和管理聊天消息。
4.数据库：用于存储用户信息、订单信息、聊天消息等。

其中，平台服务器包含：
- 匿名身份管理模块；
- 订单认证模块；
- 消息转发模块；
- 日志记录模块；
- 管理员审计模块；
- 条件溯源模块。

## 技术栈


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


## 页面入口


## 演示流程

## 核心安全机制

## 测试说明

## 已知限制

## 后续优化方向