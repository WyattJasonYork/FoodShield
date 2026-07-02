# FoodShield

FoodShield 是一个面向外卖平台订单通信场景的匿名订单认证与可审计通信系统。系统以“日常匿名、通信加密、审计可验、投诉可溯、篡改必现”为目标，支持匿名 PID、HMAC-SM3 订单 Token、SM4-CBC 消息加密存储、WebSocket 实时通信、Hash-only 管理员审计、三端 Merkle Root 一致性验证和审批式条件溯源。

## 核心特性

- 匿名身份保护：用户注册后由后端生成 PID，用户端和骑手端不展示 PID。
- 订单认证：用户创建订单后获得 HMAC-SM3 Token，进入订单通信前必须验证订单归属。
- 加密存储：聊天内容写入数据库前使用 SM4-CBC 加密，数据库中不保存聊天明文。
- 骑手认证：骑手端支持独立注册/登录，接单、入房、发消息和 Root 上报都绑定骑手会话。
- 实时通信：用户端与已接单骑手通过 Flask-SocketIO 按订单房间实时通信。
- Hash-only 审计：管理员端默认不读取聊天明文，只展示消息哈希、角色、时间戳和审计日志。
- Merkle 完整性验证：基于 SM3 消息哈希构建 Merkle Root，检测消息内容或数据库记录篡改。
- 三端一致性：用户端、骑手端和管理员端分别持有或计算 Merkle Root，管理员可比对三方视图是否一致。
- 条件溯源：用户端/骑手端按订单提交溯源申请，管理员审批后按订单号恢复真实用户映射，并写入审计日志。
- 攻击演示与性能评估：提供本地脚本展示伪造 Token、越权、重复接单、篡改检测和关键路径耗时。

## 系统架构

### 前端展示层

- 用户端 `user.html`：注册/登录、验证码、创建订单、Token 验证、聊天、订单历史、溯源申请。
- 骑手端 `rider.html`：骑手注册/登录、订单搜索、接单、匿名聊天、Root 上报、溯源申请。
- 管理员端 `admin.html`：登录、订单审计、消息哈希查看、Merkle 快照、完整性验证、三端一致性验证、溯源审批。

### 后端服务层

后端基于 Flask 和 Flask-SocketIO，负责用户会话、骑手会话、订单创建、Token 验证、骑手接单、WebSocket 房间管理、消息落库、审计日志和管理员接口。

### 安全审计层

- `project/crypto/sm_utils.py`：SM3、HMAC-SM3 兼容封装、SM4-CBC 加解密。
- `project/crypto/pid.py`：基于 HMAC-SM3 的匿名 PID 生成。
- `project/crypto/token_utils.py`：订单 Token 生成与验证。
- `project/crypto/merkle.py`：消息哈希与 Merkle Root 构建。
- `project/server/logger.py`：Merkle 快照、完整性验证和异常定位。
- `project/server/security_audit.py`：数据库版安全审计辅助接口。

### 数据持久层

SQLite 保存用户、订单、消息密文、消息哈希、审计日志和溯源申请。当前为竞赛原型，生产环境建议迁移到 PostgreSQL 或 MySQL。

## 项目结构

```text
FoodShield/
├── project/
│   ├── crypto/                  # 国密算法、Token、PID、Merkle
│   ├── database/                # SQLite schema 与访问封装
│   ├── frontend/                # 用户端、骑手端、管理员端页面
│   ├── server/                  # Flask 主程序与审计逻辑
│   ├── tools/
│   │   ├── attack_demo.py       # 攻击/防御演示脚本
│   │   └── performance_benchmark.py
│   └── integration_demo.py      # 兼容入口，运行攻击/防御演示
├── TODO.md
├── requirements.txt
├── pyproject.toml
├── uv.lock
└── foodshield.db                # 本地演示数据库
```

## 环境要求

- Python 3.10+
- 现代浏览器：Chrome、Edge 或 Firefox
- 推荐使用虚拟环境或 uv

## 安装与启动

使用 pip：

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m project.server.app
```

Windows PowerShell 激活命令：

```powershell
.\.venv\Scripts\Activate.ps1
```

使用 uv：

```bash
uv sync
uv run python -m project.server.app
```

启动后访问：

| 页面 | 地址 |
|---|---|
| 首页 | http://127.0.0.1:5000/ |
| 用户端 | http://127.0.0.1:5000/user.html |
| 骑手端 | http://127.0.0.1:5000/rider.html |
| 管理员端 | http://127.0.0.1:5000/admin.html |

## 安全配置

竞赛本地演示可使用默认配置。只要仍使用默认密钥或默认管理员密码，服务启动时会打印红色警告。公开网络演示或部署前应设置：

```bash
export FOODSHIELD_SECRET_KEY="replace-with-random-session-secret"
export FOODSHIELD_ADMIN_USERNAME="admin"
export FOODSHIELD_ADMIN_PASSWORD="replace-with-strong-password"
export FOODSHIELD_ORDER_KEY="replace-with-order-hmac-key"
export FOODSHIELD_MASTER_KEY="replace-with-pid-master-key"
export FOODSHIELD_ORDER_ALIAS_SECRET="replace-with-order-alias-key"
export FOODSHIELD_SM4_KEY="16-byte-sm4-key"
```

Windows PowerShell 示例：

```powershell
$env:FOODSHIELD_SECRET_KEY="replace-with-random-session-secret"
$env:FOODSHIELD_ADMIN_PASSWORD="replace-with-strong-password"
```

## 推荐演示流程

1. 打开用户端，注册/登录，注意页面不展示 PID。
2. 创建订单，获得 `order_id`、`timestamp` 和 `token`。
3. 验证订单 Token，进入匿名聊天房间。
4. 打开骑手端，注册或登录骑手账号。
5. 搜索待接订单，接单并进入同一订单房间。
6. 用户端和骑手端发送多条消息，观察 Merkle Root 同步。
7. 两端分别上报本端 Root。
8. 打开管理员端登录，查看订单列表和消息哈希。
9. 生成 Merkle 快照并执行完整性验证。
10. 执行三端 Root 一致性验证。
11. 用户端或骑手端提交溯源申请，管理员审批后按订单号溯源。
12. 运行攻击演示脚本，展示伪造 Token、越权、未登录骑手接单拦截、重复接单和篡改检测。
13. 运行性能测试脚本，收集报告中的性能数据。

## 攻击/防御演示脚本

脚本默认使用 `/tmp` 下的隔离数据库，不会修改仓库中的 `foodshield.db`。

```bash
python -m project.tools.attack_demo
```

演示场景包括：

- 未登录创建订单被拒；
- 伪造 Token 验证失败；
- 其他用户越权验证订单被拒；
- 未登录骑手接单被拒；
- 重复接单被拒；
- 未登录管理员访问审计接口被拒；
- 管理员端消息接口只返回哈希，不返回 `content`；
- 直接篡改数据库消息密文后完整性验证失败；
- 管理员明文关键词扫描接口被隐私策略阻断。

历史入口仍可使用：

```bash
python -m project.integration_demo
```

## 性能测试脚本

```bash
python -m project.tools.performance_benchmark
```

可调参数：

```bash
python -m project.tools.performance_benchmark --users 20 --orders-per-user 10 --messages-per-order 30
```

脚本会生成用户、骑手、订单和消息数据。输出指标包括 Token 生成、Token 验证、SM4 加解密往返、消息写入、Merkle 快照和完整性验证的平均耗时、P95 和最大耗时。报告中可用这些数据说明系统关键路径性能。

## 核心安全机制

### 匿名 PID

PID 由后端使用 `HMAC-SM3(K_master, user_id || r)` 生成。用户端和骑手端不展示 PID，管理员端也不把 PID 作为常规查询入口。

### 骑手认证与订单绑定

骑手拥有独立账号表和后端内部 `rider_pid`。骑手注册/登录后才能查看可接订单、接单、进入订单房间、发送骑手消息、提交骑手侧溯源申请和上报骑手端 Merkle Root。订单被接单后写入 `rider_id`，其他骑手不能进入该订单房间或冒充发送消息。

### HMAC-SM3 订单 Token

Token 绑定 `order_id|pid|timestamp`。验证时后端根据当前登录用户和订单归属查询 PID，不信任前端提交的 PID。

### SM4-CBC 加密存储

聊天明文写入数据库前加密，数据库保存的是 `IV + ciphertext` 的十六进制字符串。完整性由消息哈希和 Merkle Root 提供。

### SM3 消息哈希与 Merkle Root

每条消息哈希定义为：

```text
SM3(order_id | sender_pid | role | content | timestamp)
```

订单内消息哈希按固定顺序作为 Merkle 叶子节点，生成订单级 Merkle Root。验证时系统重新解密消息、重算哈希并与快照 Root 对比。

### Hash-only 管理员审计

管理员端查看通信记录时不返回聊天 `content` 字段，只展示 `msg_id`、角色、时间戳和 SM3 消息哈希。这样可以演示“平台可审计，但管理员默认不读私聊内容”的最小知晓原则。

### 条件溯源

溯源以订单号和审批流程触发。用户端/骑手端提交溯源申请，管理员审批后系统按订单映射恢复真实用户信息，所有操作写入 `audit_logs`。

## 竞赛报告建议

- 攻击拦截：展示伪造 Token、越权访问、未登录骑手接单、重复接单、未登录管理员访问、数据库篡改检测。
- 隐私保护：说明 PID 后端托管、骑手端不见用户 PID、骑手消息使用后端内部 rider_pid、管理员端 hash-only、备注/标签不在管理员端展示。
- 完整性证明：展示消息哈希、Merkle Root、快照、VERIFY_OK/VERIFY_FAIL 和异常 `stored_hash vs expected_hash`。
- 性能评估：用性能脚本生成不同消息量下的 Token、SM4、Merkle 和验证耗时表。
- 工程化说明：环境变量密钥、启动自检、审计日志、隔离演示脚本、可迁移数据库方案。

## 已知限制

- 当前仍是竞赛原型，默认运行在 `http://127.0.0.1:5000`，生产环境应启用 HTTPS/WSS。
- SQLite 适合原型验证，高并发生产场景建议迁移到 PostgreSQL。
- 骑手已支持原型级注册/登录和订单绑定，后续可增加实名认证、骑手资质审核和更细粒度 RBAC。
- SM4-CBC 提供机密性，完整性由应用层 SM3/Merkle 负责；生产环境可考虑认证加密模式。
- PID 映射仍由平台保存，远期可研究盲签名、零知识证明、TEE 或多方审批来降低平台单点信任。
