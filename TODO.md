# FoodShield 竞赛前待办清单

> 更新: 2026-06-24 | 整合 6.22 导师对接意见 + 自检分析 | 分支: `fix/crypto-algorithm-exchange/JiangLiyang`

---

## 🔴 P0 — 安全基础修复（阻塞性，必须先做）

- [ ] **所有硬编码密钥改为环境变量**
  - `app.config["SECRET_KEY"]` → `FOODSHIELD_SECRET_KEY`（`server/app.py:20`）
  - `K_ORDER = "FoodShield"` → `FOODSHIELD_ORDER_KEY`（`crypto/token_utils.py:4`）
  - K_MASTER → `FOODSHIELD_MASTER_KEY`（`server/app.py:214` 调用处）
  - 启动时检测：若密钥仍为默认值 → 终端打印 **红色警告**
  - SM4 密钥已有 `FOODSHIELD_SM4_KEY` 支持 ✅，确认默认值策略

- [ ] **管理员默认密码警告**
  - 默认 `admin/admin123456`（`server/app.py:22`）
  - 启动时检测 → 仍为默认值则打印警告

- [ ] **README 与代码同步**
  - "HMAC-SHA256" → "HMAC-SM3"
  - "SHA-256" → "SM3"
  - 补充 SM4-CBC 加密存储说明
  - `crypto/` 目录列表补充 `sm_utils.py`

---

## 🟠 方向 A — 隐私强化（最小知晓原则）

> **核心思想**: 各方只看到其完成工作所必需的最少信息。
> 管理员不应看到聊天内容明文，骑手不应看到用户 PID，备注对管理员不可见。

- [ ] **A1 — 管理员端不存储/不展示消息明文，只保留哈希**
  - 当前状态：消息 `content` 字段用 SM4-CBC 加密存储于 DB，管理员查看时服务端解密返回明文
  - 目标：管理员**完全不能看到消息内容**。管理员只能看到每条消息的 **SM3 哈希值** + 元数据（时间、角色、msg_id、sender_pid）
  - 核心原则：**管理员不需要读用户聊天内容**——Merkle 完整性验证只需要哈希值，溯源只需要确定"谁发了违规消息"。消息明文对管理员没有合法查看需求
  - 改动点：
    - `server/app.py` 中 `/admin/messages/<order_id>` API → 返回的消息列表**彻底移除 `content` 字段**（不返回 null，字段不存在）
    - `admin.html` 中消息表格**完全删除"内容"列**
    - DB 中的 `content` 密文保留（Merkle 验证时后端内部解密重算哈希，这发生在服务端内存中，不暴露给管理员）
    - 管理员端的所有视图和 API 均不包含消息明文

- [ ] **A2 — 用户注册后 PID 不直接展示**
  - 当前状态：注册成功即返回并页面显示 PID
  - 目标：PID 对用户**不可见**——系统内部使用，用户不需要知道自己的 PID
  - 改动点：
    - 注册成功只显示 `user_id` 和 `username`，不返回 `pid`
    - 创建订单时后台自动通过 `user_id` 查询 PID，无需用户手动输入
    - 用户端不再有 PID 输入框和显示区

- [ ] **A3 — 骑手不能看到用户 PID**
  - 当前状态：聊天消息的 `sender_pid` 通过 WebSocket 广播到房间内所有人
  - 目标：骑手看到的消息中，用户发送者的身份标识为 `"用户"` 或匿名昵称，而非 PID
  - 改动点：
    - `send_message` WebSocket 事件中 → 广播给骑手的消息里 `sender_pid` 替换为角色别名
    - 或在前端 `rider.html` 中接收消息时过滤显示

- [ ] **A4 — 订单备注/标签（用户/骑手可添加，管理员不可见）**
  - 新功能：用户下单时可添加备注（如"放门口"），骑手可添加标签（如"已到达"）
  - 约束：备注/标签对管理员**不可见**
  - 改动点：
    - `orders` 表新增 `note` 列（TEXT，SM4 加密存储）
    - 用户端 `create_order` API 新增 `note` 字段
    - 骑手端新增"添加标签"API
    - 管理员端不展示 `note` 字段

---

## 🟠 方向 B — 认证协议完善（防机器注册 + 真正认证）

> **核心改进**: 从"声明式注册"升级为"口令+验证码"的真正认证协议。

- [x] **B1 — 用户注册加入口令** ✅
  - `users` 表新增 `password_hash` + `salt` 列
  - SM3(salt + password) 存储，hmac.compare_digest 防时序
  - `/login`、`/logout`、`/user/session` API 新增
  - 注册即自动登录（session 机制）

- [x] **B2 — 验证码防机器注册** ✅
  - 数学题方案（a ± b = ?），答案存 Flask session
  - `/captcha` GET API，注册时校验，一次性使用
  - 短密码拒绝（<6 位）、两次密码不一致拒绝、验证码错误拒绝

---

## 🟠 方向 C — 溯源模型重构（投诉驱动 + 三方 Merkle 共识）

> **核心改进**: 从"管理员单向 PID 查询"改为"用户/骑手投诉驱动、按订单号溯源"。
> 从"服务端单方持有 Merkle Root"改为"三方各自计算并比对 Root"。

- [ ] **C1 — 溯源流程改为按订单号投诉驱动**
  - 当前状态：管理员在管理员端输入 PID → 直接查出真实用户
  - 目标：
    1. 用户端/骑手端新增 **"投诉"按钮** → 提交投诉请求（含订单号 + 投诉原因 + 违规关键词）
    2. 管理员收到投诉 → 对**该订单**进行完整性验证
    3. 验证通过 → 在订单消息中**关键词检索** → 命中则溯源定位发送者 PID
    4. 验证失败（篡改检出）→ 阻断溯源
    5. 关键词不命中 → 拒绝溯源（防止恶意投诉）
  - 改动点：
    - `orders` 表新增 `complaints` 列（JSON，记录投诉信息）
    - 新增 `/complaint` API（用户/骑手提交投诉）
    - `/admin/trace` API 重构 → 输入参数改为 `order_id` + `keyword`，而非 `pid`
    - 用户端/骑手端新增投诉入口

- [ ] **C2 — 三方 Merkle Root 共识**
  - 当前状态：Merkle Root 仅在服务端 `audit_logs` 表中
  - 目标：
    1. 每次消息发送后 → 服务端广播最新 Merkle Root 给房间内**所有角色**
    2. 用户端/骑手端**各自保存**收到的 Merkle Root（存 localStorage）
    3. 管理员验证时 → 比较三方持有的 Root 是否一致
    4. 不一致 → 说明某一方记录被篡改，审计警报
  - 改动点：
    - 每条消息后 WebSocket 广播新增 `merkle_root` 字段
    - 用户端/骑手端 `receive_message` 事件处理中保存 `merkle_root` 到本地
    - `audit_logs` 表新增 `client_merkle_root` 字段（记录客户端上报的 Root）
    - `/admin/verify` API → 增加三方比对逻辑

---

## 🟡 P1 — 工程质量 + 演示效果

- [ ] **单元测试**（pytest）
  - `tests/test_sm_utils.py` — SM3 哈希、SM4 加解密往返、HMAC-SM3
  - `tests/test_pid.py` — PID 确定性、唯一性
  - `tests/test_token_utils.py` — Token 生成/验证/过期/伪造拒绝
  - `tests/test_merkle.py` — Merkle 构建、根计算、篡改检测

- [ ] **篡改检测可视化**
  - 验证失败时在消息列表中**红色高亮**标记被篡改消息
  - 显示 `stored_hash vs expected_hash` 对比

- [ ] **三个端口搜索功能**
  - 用户端：搜索自己的历史订单
  - 骑手端：搜索可接订单
  - 管理员端：搜索订单（已有基础，完善）

- [ ] **用户订单历史**
  - 用户登录后可见自己的历史订单列表
  - 点击可查看订单状态、通信记录

- [ ] **前端体验优化**
  - 聊天区域自动滚到底部
  - 关键操作增加状态提示动画
  - Merkle Root 展示截断 + 悬停完整值

- [ ] **竞赛材料**
  - 演示录屏、答辩 PPT

---

## 🟢 P2 — 锦上添花

- [ ] 启动时配置自检（密钥检查、依赖检查）
- [ ] `integration_demo.py` 与新架构对齐
- [ ] 代码关键路径注释补全
- [ ] Merkle 树叶子节点定义在注释/文档中明确说明

---

## 🔮 远期

- [ ] HTTPS/WSS 传输层加密
- [ ] 骑手独立注册与实名认证
- [ ] 管理员 RBAC + 双因子溯源审批
- [ ] SQLite → PostgreSQL（SQLAlchemy）
- [ ] Docker 容器化
- [ ] 盲签名/零知识证明（消除平台单方面溯源能力）
- [ ] 区块链存证 Merkle Root
- [ ] TEE 可信溯源计算

---

## 📋 实施进度

```
P0（安全基础）—— 待做
  ↓
方向B（认证完善）—— ✅ 已完成
  ↓
方向A（隐私强化）—— 当前进行中
  ↓
方向C（溯源重构）
  ↓
P1（测试+演示）
  ↓
P2（收尾）
```
