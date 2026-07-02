# FoodShield 竞赛前待办清单

> 更新: 2026-07-02 | 当前状态校准 + P0 修复 + 骑手注册认证 + 攻击/性能脚本补充

---

## 已完成

- [x] **P0 密钥环境变量化**
  - `FOODSHIELD_SECRET_KEY`
  - `FOODSHIELD_ORDER_KEY`
  - `FOODSHIELD_MASTER_KEY`
  - `FOODSHIELD_ORDER_ALIAS_SECRET`
  - `FOODSHIELD_SM4_KEY`

- [x] **启动时默认配置警告**
  - 默认 session secret、管理员密码、订单密钥、PID master key、SM4 key 等仍在使用时打印红色警告。

- [x] **README 与当前代码同步**
  - 同步 HMAC-SM3、SM3、SM4-CBC、Hash-only 管理员审计、三端 Root 和攻击/性能脚本。

- [x] **A1 管理员端不展示消息明文**
  - `/admin/messages/<order_id>` 不返回 `content`。
  - 管理员页面只展示角色、时间戳、消息 Hash 和审计日志。

- [x] **A2 用户注册后 PID 不直接展示**
  - 注册、登录、会话接口不返回 PID。
  - 创建订单和验证订单由后端根据 session 查询 PID。

- [x] **A3 骑手不能看到用户 PID**
  - WebSocket 普通广播通过 `public_message()` 移除 `sender_pid`。
  - 骑手端展示订单级匿名 alias。

- [x] **B1 用户注册加入口令**
  - `password_hash`、`salt`、登录/登出/session 已实现。

- [x] **B2 验证码防机器注册**
  - 数学验证码、短密码拒绝、设备注册次数限制已实现。

- [x] **B3 骑手注册/登录与订单绑定**
  - 新增 `riders` 表和 `orders.rider_id`。
  - `/rider/register`、`/rider/login`、`/rider/logout`、`/rider/session` 已实现。
  - 骑手接单、入房、发送骑手消息、提交骑手侧溯源申请、上报骑手端 Root 均绑定骑手 session。
  - 骑手端不展示 `rider_pid`，仅后端内部用于消息哈希和审计。

- [x] **C2 三方 Merkle Root 共识**
  - 消息发送后广播 Root。
  - 用户/骑手端 localStorage 保存并可上报 Root。
  - 管理员端可执行三端一致性比对。

- [x] **用户/骑手/管理员搜索与用户订单历史**
  - 用户端订单搜索与历史。
  - 骑手端订单搜索。
  - 管理员端审计搜索。

- [x] **攻击演示脚本**
  - `python -m project.tools.attack_demo`
  - 覆盖伪造 Token、越权、未登录骑手接单、重复接单、未登录管理员、hash-only 审计、数据库篡改检测、明文关键词扫描阻断。

- [x] **性能测试脚本**
  - `python -m project.tools.performance_benchmark`
  - 生成用户、骑手、订单和消息，输出 Token、SM4、消息写入、Merkle 快照和完整性验证耗时。

- [x] **integration_demo.py 与新架构对齐**
  - 兼容入口现在调用维护中的攻击/防御演示脚本。

- [x] **管理员页面重复登录区清理**
  - 删除重复 `adminUsername/adminPassword` DOM，统一登录流程。

---

## 待确认设计

- [ ] **C1 投诉关键词与 Hash-only 管理员边界如何取舍**
  - 原导师建议：投诉中带违规关键词，管理员验证后检索明文，命中后溯源。
  - 当前实现：管理员不读取聊天明文，明文关键词扫描接口被禁用。
  - 建议方案：
    - 保持 hash-only 管理员原则；
    - 投诉方提交 `msg_id`、消息 Hash、投诉原因和本端证据摘要；
    - 管理员先做 Merkle 完整性验证，再审批订单号溯源；
    - 报告中说明这是“最小知晓 + 审批式溯源”的安全边界。
  - 如必须实现关键词命中，需要明确“管理员端可在服务端内存中临时检索明文，但不返回明文”的例外策略。

---

## P1 下一步

- [ ] **pytest 单元测试**
  - `tests/test_sm_utils.py`：SM3、HMAC-SM3、SM4 往返。
  - `tests/test_token_utils.py`：Token 生成、验证、过期、伪造拒绝。
  - `tests/test_merkle.py`：根计算、奇数叶子、空树、篡改检测。
  - `tests/test_admin_security.py`：管理员未登录拒绝、消息接口不返回 `content`。
  - `tests/test_rider_auth.py`：骑手注册、登录、未登录接单拒绝、非接单骑手入房拒绝。

- [ ] **篡改检测可视化**
  - VERIFY_FAIL 时在管理员页面列出异常 `msg_id`。
  - 展示 `stored_hash` 和 `expected_hash` 对比。
  - 可选：通信记录表中高亮异常消息哈希。

- [ ] **备注/标签加密策略补齐**
  - 当前 `remark/tag/delivery_note` 已有字段和页面展示，但未加密存储。
  - 建议将用户私有备注和骑手标签拆分清楚，并对非配送必要字段做 SM4 加密。

- [ ] **前端体验优化**
  - Merkle Root 截断展示 + hover 完整值。
  - 操作成功/失败状态提示统一。
  - 管理员 VERIFY_FAIL 结果更醒目。

- [ ] **竞赛材料**
  - 演示录屏。
  - 答辩 PPT。
  - 攻击拦截表、性能测试表、隐私边界图。

---

## P2 锦上添花

- [ ] **双管理员审批溯源**
  - 更好解释“防管理员滥权”。

- [ ] **Merkle Proof**
  - 对单条消息生成 proof，展示 `O(log n)` 验证优势。

- [ ] **审计报告导出**
  - 管理员一键导出订单审计 JSON/PDF。

- [ ] **Docker 容器化**
  - 方便答辩现场复现。

- [ ] **SQLite WAL / PostgreSQL 迁移方案**
  - 用于报告中的并发与工程化扩展说明。

---

## 远期方向

- [ ] HTTPS/WSS。
- [ ] 骑手实名认证与资质审核。
- [ ] 管理员 RBAC + 双因子/双人溯源审批。
- [ ] 区块链或可信时间戳存证 Merkle Root。
- [ ] 盲签名/零知识证明，降低平台单方溯源能力。
- [ ] TEE 可信溯源计算。
