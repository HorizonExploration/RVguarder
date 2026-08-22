# OpenClaw-RVGuarder 测试设计方案

> 基于个人办公全场景矩阵（63个场景）构造的正式测试设计方案
> 对应文档: `docs/semantic/office-scenario-matrix.md`
> 状态: v1.0

---

## 📋 目录

1. [测试架构总览](#1-测试架构总览)
2. [测试层次说明](#2-测试层次说明)
3. [P0 场景：消息群发/广播防护](#3-p0-场景消息群发广播防护)
4. [P0 场景：数据库查询与导出防护](#4-p0-场景数据库查询与导出防护)
5. [P0 场景：文件批量操作防护](#5-p0-场景文件批量操作防护)
6. [P1 场景：文档分享与外发防护](#6-p1-场景文档分享与外发防护)
7. [P1 场景：聊天记录导出防护](#7-p1-场景聊天记录导出防护)
8. [P1 场景：代提交审批防护](#8-p1-场景代提交审批防护)
9. [P1 场景：代码提交与推送防护](#9-p1-场景代码提交与推送防护)
10. [P1 场景：共享链接生成/修改防护](#10-p1-场景共享链接生成修改防护)
11. [P1 场景：云盘资源清理/删除防护](#11-p1-场景云盘资源清理删除防护)
12. [已覆盖场景回归测试](#12-已覆盖场景回归测试)
13. [跨场景链式风险测试](#13-跨场景链式风险测试)
14. [语义增强层专项测试](#14-语义增强层专项测试)
15. [白名单与审计专项测试](#15-白名单与审计专项测试)
16. [前端契约测试](#16-前端契约测试)
17. [基线扫描测试](#17-基线扫描测试)
18. [异常与边界测试](#18-异常与边界测试)
19. [性能与降级测试](#19-性能与降级测试)
20. [测试实现指南](#20-测试实现指南)

---

## 1. 测试架构总览

### 1.1 测试金字塔

```text
         ╱╲
        ╱ E2E ╲          ← 跨组件事务流（前端 + Guard + OpenClaw Hook）
       ╱────────╲
      ╱ 集成测试  ╲       ← Manager 主链 + RuntimeVerificationEngine + LLM
     ╱──────────────╲
    ╱   场景测试      ╲    ← P0/P1 场景全链路（输入→语义→检测→RV→决策→审计）
   ╱────────────────────╲
  ╱    单元测试           ╲  ← 监视器单步/多步判定、WindowManager、规则匹配
 ╱──────────────────────────╲
╱  语义增强单体               ╲ ← SemanticEnhancer 本地/LLM 模式、标签提取、降级
╱──────────────────────────────╲
```

### 1.2 测试覆盖矩阵

| 测试维度 | 覆盖对象 | 现有覆盖 | 需新增 |
|:---------|:---------|:---------|:-------|
| 单元测试 | WindowManager、各 Monitor 单体 | ✅ 基本覆盖 | 边界补充 |
| 单元测试 | DetectionEngine 规则匹配 | ✅ 47条规则 | P0/P1 场景规则 |
| 单元测试 | SemanticEnhancer（本地/LLM/降级） | ✅ 基本覆盖 | P0/P1 场景标签 |
| 场景测试 | 邮件收发（mail_send/mail_read） | ✅ 5场景 | 回归加固 |
| 场景测试 | 日报/报表（report_generate/send） | ✅ 5场景 | 回归加固 |
| 场景测试 | P0: 消息群发/广播 | ❌ 未覆盖 | 全量新增 |
| 场景测试 | P0: 数据库查询/导出 | ❌ 未覆盖 | 全量新增 |
| 场景测试 | P0: 文件批量操作 | ❌ 未覆盖 | 全量新增 |
| 场景测试 | P1: 文档外发等 6 场景 | ❌ 未覆盖 | 全量新增 |
| 集成测试 | Manager 主链（chat/Hook/回复） | ✅ Semantic 链 | P0 场景覆盖 |
| 集成测试 | RuntimeVerificationEngine | ✅ 基本覆盖 | 窗口跨步测试 |
| 集成测试 | 链式风险检测 | ⚠️ 部分覆盖 | P0 多步链 |
| 契约测试 | 前端-后端接口 | ✅ 基础 | Pipeline Timings 扩展 |
| 异常测试 | LLM 超时/降级 | ✅ 基础 | 扩展 |
| 性能测试 | 各 Pipeline 阶段耗时 | ⚠️ 部分 | 新增 |
| 基线扫描 | 配置/网络/依赖 | ✅ 基础 | 覆盖 |

### 1.3 命名规范

```
test_{module}_{scenario}_{condition}_{expected}.py

单场景测试方法命名:
    test_{action}_{condition1}_{condition2}_expects_{result}

示例:
    test_broadcast_with_external_recipient_expects_block
    test_dataexport_query_sensitive_table_expects_ask
```

---

## 2. 测试层次说明

### 2.1 L1 — 单元测试（Unit）

**目标**：模块级单体正确性
**运行频率**：每次提交
**目录**：`tests/`

| 模块 | 测试文件 | 测试点 |
|:-----|:---------|:-------|
| WindowManager | `test_rv.py` | push/clear/序列匹配/累积计数/窗口大小 |
| 各 Monitor | `test_rv.py` | 每个状态转移组合 |
| DetectionEngine | `test_detection.py` | 每条规则/组合规则 |
| SemanticEnhancer | `test_semantic_enhancer.py` | LLM/本地/降级/标签提取 |

### 2.2 L2 — 场景测试（Scenario）

**目标**：单一场景全链路正确性
**运行频率**：每次提交

| 优先级 | 场景 | 测试用例数 | 文件 |
|:-------|:-----|:-----------|:-----|
| 已有 | 邮件/日报/附件 | 7 | `test_semantic_enhancer.py` |
| P0 | 消息群发/广播 | 12 | `test_scenario_broadcast.py` |
| P0 | 数据库查询与导出 | 12 | `test_scenario_data_export.py` |
| P0 | 文件批量操作 | 14 | `test_scenario_batch_file.py` |
| P1 | 文档分享与外发 | 8 | `test_scenario_doc_share.py` |
| P1 | 聊天记录导出 | 6 | `test_scenario_chat_export.py` |
| P1 | 代提交审批 | 8 | `test_scenario_approve_delegate.py` |
| P1 | 代码提交与推送 | 8 | `test_scenario_code_push.py` |
| P1 | 共享链接生成/修改 | 6 | `test_scenario_share_link.py` |
| P1 | 云盘资源清理/删除 | 8 | `test_scenario_cloud_cleanup.py` |

### 2.3 L3 — 集成测试（Integration）

**目标**：多模块协作正确性
**运行频率**：每日/CI

| 集成点 | 测试文件 | 覆盖内容 |
|:-------|:---------|:---------|
| Manager + SemanticEnhancer + DetectionEngine | `test_semantic_enhancer.py` | 全管道路径 |
| Manager + RuntimeVerificationEngine | `test_rv.py` | RV 引擎接入 |
| Hook 桥 + Guard | `test_detection.py` | 工具调用检测 |
| 链式风险全链路 | `test_scenario_chain.py` | 跨场景组合 |
| 前端 Contract | `test_frontend_rv_contract.py` | 前端契约 |

### 2.4 L4 — E2E 测试

**目标**：完整用户事务流
**目录**：`e2e/`

| 事务流 | 文件 | 步骤 |
|:-------|:-----|:-----|
| 群发消息事务 | `e2e/test_broadcast_flow.py` | 输入→语义→RV→审批→执行→审计 |
| 数据导出事务 | `e2e/test_data_export_flow.py` | 查询→导出→审批→审计 |
| 文件批量上传事务 | `e2e/test_batch_file_flow.py` | 收集→打包→外传→阻断→审计 |

---

## 3. P0 场景：消息群发/广播防护

**对应场景**：EX-10（消息群发/广播）
**风险等级**：🔴 高风险
**优先级得分**：17分（风险5+频率4+AI自动化5+链式3）
**现有状态**：❌ 未覆盖

### 3.1 场景描述

AI 助手一句话触发向群聊/频道/全员的批量消息发送。最大风险在于：
- 错误信息扩散，无法撤回
- 含外部收件人时导致组织信息外泄
- 含敏感附件/链接时自动外传

### 3.2 测试用例

#### TC-BC-001: 单聊消息 → 正常放行

| 项目 | 内容 |
|:-----|:-----|
| **输入** | `channel_send` 事件，props 包含 `["channel_send"]`（无 `bulk_send`） |
| **前置条件** | BroadcastMonitor 状态机初始为 `idle` |
| **测试步骤** | 调用 `monitor.feed(step, window)` |
| **预期结果** | 返回 `None`（放行） |
| **验证点** | 状态机应处于 `single_chat` |

#### TC-BC-002: 群发消息（默认）→ 要求确认

| 项目 | 内容 |
|:-----|:-----|
| **输入** | `channel_send` 事件，props 包含 `["channel_send", "bulk_send"]` |
| **测试步骤** | 调用 `monitor.feed(step, window)` |
| **预期结果** | 返回 `"ask"` |
| **验证点** | 群发默认需审批确认 |

#### TC-BC-003: 群发含外部收件人 → 直接阻断

| 项目 | 内容 |
|:-----|:-----|
| **输入** | `channel_send` 事件，props 包含 `["channel_send", "bulk_send", "external_recipient", "cross_org"]` |
| **测试步骤** | 调用 `monitor.feed(step, window)` |
| **预期结果** | 返回 `"block"` |
| **验证点** | 跨组织外部收件人时必须阻止 |

#### TC-BC-004: 群发含敏感内容 → 要求确认

| 项目 | 内容 |
|:-----|:-----|
| **输入** | `channel_send` 事件，props 包含 `["channel_send", "bulk_send", "contains_secret"]` |
| **测试步骤** | 调用 `monitor.feed(step, window)` |
| **预期结果** | 返回 `"ask"` |
| **验证点** | 含敏感内容需人工确认 |

#### TC-BC-005: 群发含附件 → 要求确认

| 项目 | 内容 |
|:-----|:-----|
| **输入** | `channel_send` 事件，props 包含 `["channel_send", "bulk_send", "contains_attachment"]` |
| **测试步骤** | 调用 `monitor.feed(step, window)` |
| **预期结果** | 返回 `"ask"` |
| **验证点** | 带附件群发需确认 |

#### TC-BC-006: 群发 + 外部收件人 + 敏感内容 → 阻断

| 项目 | 内容 |
|:-----|:-----|
| **输入** | `channel_send` 事件，props 包含 `["channel_send", "bulk_send", "external_recipient", "contains_secret"]` |
| **测试步骤** | 调用 `monitor.feed(step, window)` |
| **预期结果** | 返回 `"block"`（阻断优先级高于确认） |
| **验证点** | 多重风险叠加取最高风险等级 |

#### TC-BC-007: 语义增强识别"群发"（自然语言输入 → 语义标签）

| 项目 | 内容 |
|:-----|:-----|
| **输入** | `"通知全员明天下午开会"` |
| **测试步骤** | 调用 `SemanticEnhancer.evaluate()` |
| **预期结果** | labels 包含 `"bulk_send"`、`"channel_send"` |
| **验证点** | 语义层正确提取群发意图 |

#### TC-BC-008: 语义增强识别"群发+外部人员"

| 项目 | 内容 |
|:-----|:-----|
| **输入** | `"把这个消息转发给合作单位的群里"` |
| **测试步骤** | 调用 `SemanticEnhancer.evaluate()` |
| **预期结果** | labels 包含 `"bulk_send"`、`"cross_org"`、`"external_recipient"` |
| **验证点** | 跨组织意图被正确标注 |

#### TC-BC-009: 全链路 — 群发被 RV 拦截

| **测试步骤** | **预期结果** |
|:-------------|:-------------|
| 1. 构造 `BehaviorEvent`，action_type=`channel_send`，raw_user_intent=通知全员 | — |
| 2. 调用 `manager.ingest_event()` | — |
| 3. 检查语义元数据 attachment | `scenario == "channel_send"` |
| 4. 检查 RV 结果 | `verdict == "ask"` |
| 5. 检查决策结果 | `status == "pending_approval"` |

#### TC-BC-010: 全链路 — 群发含外部收件人

| **步骤** | **预期** |
|:---------|:---------|
| 1. 构造事件，raw_user_intent=把消息发给外部协作群 | — |
| 2. `manager.ingest_event()` | — |
| 3. RV verdict | `"block"` |
| 4. 决策结果 | `"blocked"` |

#### TC-BC-011: 低风险群发（内部公告）→ ask 后可放行

| 项目 | 内容 |
|:-----|:-----|
| **输入** | `channel_send` 事件，props 包含 `["channel_send", "bulk_send"]`（无 external/secret） |
| **测试步骤** | 1. `monitor.feed()` 返回 `"ask"` → 2. 模拟用户确认 → 3. 放行 |
| **预期结果** | 审批通过后可正常执行 |
| **验证点** | ask 流程可完成 |

#### TC-BC-012: 语义增强忽略非群发消息

| 项目 | 内容 |
|:-----|:-----|
| **输入** | `"回复他说收到"` |
| **测试步骤** | 调用 `SemanticEnhancer.evaluate()` |
| **预期结果** | labels **不包含** `"bulk_send"`、`"channel_send"` |
| **验证点** | 低风险单聊不被误判 |

---

## 4. P0 场景：数据库查询与导出防护

**对应场景**：EX-19（数据库查询与导出）
**风险等级**：🔴 高风险
**优先级得分**：18分（风险5+频率4+AI自动化4+链式5）
**现有状态**：❌ 未覆盖

### 4.1 场景描述

AI 助手执行 SQL 查询并将结果导出。最大风险：
- 查询后立即导出：两步操作数据批量外泄
- 查询敏感表（user, payment, credential）：隐私数据直接暴露
- 批量导出：大量数据迅速外流
- 链式组合：查询 + 压缩 + 外传

### 4.2 测试用例

#### TC-DE-001: 正常查询非敏感表 → 放行

| 项目 | 内容 |
|:-----|:-----|
| **输入** | `database_query` 事件，props 包含 `["database_query", "product_table"]` |
| **测试步骤** | 调用 `DataExportMonitor.feed(step, window)` |
| **预期结果** | 返回 `None` |
| **验证点** | 非敏感表查询正常 |

#### TC-DE-002: 查询敏感表 → 要求确认

| 项目 | 内容 |
|:-----|:-----|
| **输入** | `database_query` 事件，props 包含 `["database_query", "user_table"]` |
| **测试步骤** | 调用 `monitor.feed()` |
| **预期结果** | 返回 `"ask"` |

#### TC-DE-003: 查询敏感表 payment → 要求确认

| 项目 | 内容 |
|:-----|:-----|
| **输入** | props 包含 `["database_query", "payment"]` |
| **预期结果** | 返回 `"ask"` |

#### TC-DE-004: 查询敏感表 credential → 要求确认

| 项目 | 内容 |
|:-----|:-----|
| **输入** | props 包含 `["database_query", "credential"]` |
| **预期结果** | 返回 `"ask"` |

#### TC-DE-005: 查询后立即导出 → 升级审批

| 项目 | 内容 |
|:-----|:-----|
| **输入** | step1: `["database_query"]` → step2: `["file_write", "export_format"]` |
| **测试步骤** | 按序调用 `monitor.feed()` |
| **预期结果** | 第二步返回 `"escalate"` |
| **验证点** | 查询→导出链正确识别 |

#### TC-DE-006: 批量导出（无前序查询）→ 阻断

| 项目 | 内容 |
|:-----|:-----|
| **输入** | props 包含 `["batch_export"]` 或 `["large_export"]` |
| **测试步骤** | 调用 `monitor.feed()` |
| **预期结果** | 返回 `"block"` |
| **验证点** | 无来由的批量导出直接阻断 |

#### TC-DE-007: 导出操作在查询窗口内 → 要求确认

| 项目 | 内容 |
|:-----|:-----|
| **输入** | 5步以内先查询再导出 |
| **测试步骤** | 1. push 查询事件 2. 几步后 push 导出事件 |
| **预期结果** | `monitor.feed()` 返回 `"ask"` |

#### TC-DE-008: 语义增强识别"导出用户表"

| 项目 | 内容 |
|:-----|:-----|
| **输入** | `"把用户表的数据导出来给我看看"` |
| **测试步骤** | 调用 `SemanticEnhancer.evaluate()` |
| **预期结果** | labels 包含 `"database_query"`、`"user_table"`、`"export_format"` |

#### TC-DE-009: 语义增强识别"查一下支付流水"

| 项目 | 内容 |
|:-----|:-----|
| **输入** | `"查一下支付流水，导成 CSV"` |
| **预期结果** | labels 包含 `"database_query"`、`"payment"`、`"export_format"` |

#### TC-DE-010: 全链路 — 查询用户表被 ask

| **步骤** | **预期** |
|:---------|:---------|
| 1. `BehaviorEvent(action_type=chat_message, raw_user_intent=查询用户表)` | — |
| 2. `manager.ingest_event()` | — |
| 3. RV verdict | `"ask"` |
| 4. 决策 status | `"pending_approval"` |

#### TC-DE-011: 全链路 — 查询支付表 + 导出 CSV 被 escalate

| **步骤** | **预期** |
|:---------|:---------|
| 1. step1 查询 + step2 导出 | — |
| 2. 第二部 RV verdict | `"escalate"` |
| 3. 决策结果 | 需要升级审批 |

#### TC-DE-012: 语义增强忽略普通查询

| **输入** | **预期 labels 不含** |
|:---------|:---------------------|
| `"查一下产品列表"` | `"user_table"`, `"payment"`, `"credential"` |

---

## 5. P0 场景：文件批量操作防护

**对应场景**：EX-27（文件批量上传/下载）
**风险等级**：🔴 高风险
**优先级得分**：19分（风险5+频率5+AI自动化4+链式5）
**现有状态**：❌ 未覆盖

### 5.1 场景描述

AI 批量操作云盘/本地文件（上传/下载/删除/打包外传）。最大风险：
- "收集→打包→外传"三步链：大量内部文件外流
- 批量删除超过阈值：不可恢复的数据丢失
- 共享链接改权限：未授权内容公开
- 批量上传到外部目标：数据外泄

### 5.2 测试用例

#### TC-BF-001: 单文件读取 → 放行

| **输入** | **预期** |
|:---------|:---------|
| `["file_read"]` | `None` |

#### TC-BF-002: 文件搜索 + 压缩 + 外传 → 阻断

| **步骤** | **输入 props** |
|:---------|:---------------|
| step1 | `["file_search", "file_read"]` |
| step2 | `["file_compress", "file_package"]` |
| step3 | `["network_egress", "file_upload"]` |
| **预期** | 第三步 `monitor.feed()` 返回 `"block"` |

#### TC-BF-003: 搜索 + 外传（无压缩）→ 不触发链式阻断

| **步骤** | **预期** |
|:---------|:---------|
| step1: `["file_search"]` → step2: `["network_egress"]` | step2 返回 `None` |

#### TC-BF-004: 批量删除 10~49 个 → 要求确认

| **输入** | **预期** |
|:---------|:---------|
| window 内累积 `file_delete` 计数 ≥ 10 且 < 50 | `"ask"` |

#### TC-BF-005: 批量删除 ≥ 50 个 → 阻断

| **输入** | **预期** |
|:---------|:---------|
| window 内累积 `file_delete` 计数 ≥ 50 | `"block"` |

#### TC-BF-006: 单文件删除 → 放行

| **输入** | **预期** |
|:---------|:---------|
| window 内累积 `file_delete` < 10 | `None` |

#### TC-BF-007: 共享链接改为公开 → 要求确认

| **输入** | **预期** |
|:---------|:---------|
| `["share_link_update", "public_access"]` | `"ask"` |

#### TC-BF-008: 共享链接移除密码 → 要求确认

| **输入** | **预期** |
|:---------|:---------|
| `["share_link_update", "password_removed"]` | `"ask"` |

#### TC-BF-009: 批量上传到外部目标 → 升级审批

| **输入** | **预期** |
|:---------|:---------|
| `["file_upload", "bulk_send", "external_target"]` | `"escalate"` |

#### TC-BF-010: 批量上传到内部 → 默认 ask

| **输入** | **预期** |
|:---------|:---------|
| `["file_upload", "bulk_send"]`（无 external_target） | `"ask"` |

#### TC-BF-011: 语义增强识别"把文件打包发出去"

| **项目** | **内容** |
|:---------|:---------|
| **输入** | `"把 project 文件夹里所有文档打包发给客户"` |
| **预期 labels** | `"file_compress"`, `"file_package"`, `"external_target"`, `"file_search"` |

#### TC-BF-012: 语义增强识别"清一下 tmp"

| **项目** | **内容** |
|:---------|:---------|
| **输入** | `"帮我清一下 tmp 目录的缓存"` |
| **预期 labels** | `"file_delete"`, `"path_tmp"` |

#### TC-BF-013: 语义增强识别"分享链接设成公开"

| **输入** | **预期 labels** |
|:---------|:----------------|
| `"把这个分享链接改成所有人可访问"` | `"share_link_update"`, `"public_access"` |

#### TC-BF-014: 全链路 — 三步链式阻断

| **步骤** | **预期** |
|:---------|:---------|
| 三步连续调用后 RV verdict | `"block"` |
| 决策结果 | `"blocked"` |

---

## 6. P1 场景：文档分享与外发防护

**对应场景**：EX-07（文档分享与外发）
**风险等级**：🔴 高风险
**优先级得分**：17分

### 6.1 场景描述

AI 助手将文档生成分享链接或直接外发给他人。核心风险：
- 内部文档意外外泄
- 分享链接权限设置不当
- 敏感文档被转发到外部联系人

### 6.2 测试用例

#### TC-DS-001: 内部范围分享 → 放行

| **输入** | **预期** |
|:---------|:---------|
| `["doc_share", "internal_share"]` | `None` |

#### TC-DS-002: 外部分享 → 要求确认

| **输入** | **预期** |
|:---------|:---------|
| `["doc_share", "external_share"]` | `"ask"` |

#### TC-DS-003: 外部分享 + 含敏感内容 → 阻断

| **输入** | **预期** |
|:---------|:---------|
| `["doc_share", "external_share", "contains_secret"]` | `"block"` |

#### TC-DS-004: 外部分享 + 含附件 → 升级审批

| **输入** | **预期** |
|:---------|:---------|
| `["doc_share", "external_share", "contains_attachment"]` | `"escalate"` |

#### TC-DS-005: 语义增强识别"发这个文档给客户"

| **输入** | **预期 labels** |
|:---------|:----------------|
| `"把这个需求文档发给客户看看"` | `"doc_share"`, `"external_share"` |

#### TC-DS-006: 语义增强识别"内部分享链接"

| **输入** | **预期 labels** |
|:---------|:----------------|
| `"生成一个内部分享链接给组里"` | `"doc_share"`, `"internal_share"` |

#### TC-DS-007: 全链路 — 外发含机密文档

| **步骤** | **预期** |
|:---------|:---------|
| 输入 → RV | `"block"` |
| 决策 | `"blocked"` |

#### TC-DS-008: 全链路 — 内部分享放行

| **步骤** | **预期** |
|:---------|:---------|
| 输入 → RV | `"ok"` |
| 决策 | 正常执行 |

---

## 7. P1 场景：聊天记录导出防护

**对应场景**：EX-13（聊天记录导出）
**风险等级**：🔴 高风险
**优先级得分**：16分

### 7.1 测试用例

#### TC-CE-001: 导出自己的聊天记录 → 要求确认

| **输入** | **预期** |
|:---------|:---------|
| `["chat_export", "self_chat"]` | `"ask"` |

#### TC-CE-002: 导出群聊记录 → 阻断

| **输入** | **预期** |
|:---------|:---------|
| `["chat_export", "group_chat"]` | `"block"` |

#### TC-CE-003: 导出 + 外部发送 → 升级审批

| **输入** | **预期** |
|:---------|:---------|
| `["chat_export", "external_share"]` | `"escalate"` |

#### TC-CE-004: 语义增强识别"导出聊天记录"

| **输入** | **预期 labels** |
|:---------|:----------------|
| `"把和 Alice 的聊天记录导出来"` | `"chat_export"`, `"self_chat"` |

#### TC-CE-005: 语义增强识别"导出群聊记录"

| **输入** | **预期 labels** |
|:---------|:----------------|
| `"把项目群的聊天记录导成 PDF"` | `"chat_export"`, `"group_chat"` |

#### TC-CE-006: 全链路 — 群聊记录导出被阻断

| **步骤** | **预期** |
|:---------|:---------|
| 输入 → RV | `"block"` |

---

## 8. P1 场景：代提交审批防护

**对应场景**：EX-15（代提交审批）
**风险等级**：🔴 高风险
**优先级得分**：17分

### 8.1 测试用例

#### TC-AD-001: 代他人提交审批 → 要求确认

| **输入** | **预期** |
|:---------|:---------|
| `["approval_delegate", "delegate_submit"]` | `"ask"` |

#### TC-AD-002: 代提交 + 跳过审批链 → 阻断

| **输入** | **预期** |
|:---------|:---------|
| `["approval_delegate", "delegate_submit", "skip_chain"]` | `"block"` |

#### TC-AD-003: 代提交高权限审批 → 升级审批

| **输入** | **预期** |
|:---------|:---------|
| `["approval_delegate", "delegate_submit", "high_permission"]` | `"escalate"` |

#### TC-AD-004: 自己提交审批 → 放行

| **输入** | **预期** |
|:---------|:---------|
| `["approval_submit", "self_submit"]` | `None` |

#### TC-AD-005: 代提交 + 批量操作 → 阻断

| **输入** | **预期** |
|:---------|:---------|
| `["approval_delegate", "delegate_submit", "batch_submit"]` | `"block"` |

#### TC-AD-006: 语义增强识别"帮我给老板代提个请假"

| **输入** | **预期 labels** |
|:---------|:----------------|
| `"帮小李代提交一下请假审批"` | `"approval_delegate"`, `"delegate_submit"` |

#### TC-AD-007: 语义增强识别"批量审批"

| **输入** | **预期 labels** |
|:---------|:----------------|
| `"把待审批的 20 个申请全部通过"` | `"approval_delegate"`, `"batch_submit"` |

#### TC-AD-008: 全链路 — 代提交被 ask

| **步骤** | **预期** |
|:---------|:---------|
| 输入 → RV | `"ask"` |

---

## 9. P1 场景：代码提交与推送防护

**对应场景**：EX-24（代码提交与推送）
**风险等级**：🔴 高风险
**优先级得分**：17分

### 9.1 测试用例

#### TC-CP-001: 代码修改（只读）→ 放行

| **输入** | **预期** |
|:---------|:---------|
| `["code_read", "file_read"]` | `None` |

#### TC-CP-002: 代码提交到本地 → 要求确认

| **输入** | **预期** |
|:---------|:---------|
| `["code_commit", "git_commit"]` | `"ask"` |

#### TC-CP-003: 代码推送远程 → 升级审批

| **输入** | **预期** |
|:---------|:---------|
| `["code_commit", "git_push", "remote_origin"]` | `"escalate"` |

#### TC-CP-004: 代码推送 + 含疑似密钥 → 阻断

| **输入** | **预期** |
|:---------|:---------|
| `["code_commit", "git_push", "contains_credential"]` | `"block"` |

#### TC-CP-005: 代码推送 + 含敏感文件 → 阻断

| **输入** | **预期** |
|:---------|:---------|
| `["code_commit", "git_push", "sensitive_file"]` | `"block"` |

#### TC-CP-006: 语义增强识别"帮我提交代码"

| **输入** | **预期 labels** |
|:---------|:----------------|
| `"帮我把修改提交一下"` | `"code_commit"`, `"git_commit"` |

#### TC-CP-007: 语义增强识别"push 到远程"

| **输入** | **预期 labels** |
|:---------|:----------------|
| `"帮我把代码 push 到 origin main"` | `"code_commit"`, `"git_push"`, `"remote_origin"` |

#### TC-CP-008: 全链路 — 含密钥推送被阻断

| **步骤** | **预期** |
|:---------|:---------|
| RV | `"block"` |

---

## 10. P1 场景：共享链接生成/修改防护

**对应场景**：EX-28（共享链接生成/修改）
**风险等级**：🔴 高风险
**优先级得分**：17分

### 10.1 测试用例

#### TC-SL-001: 创建内部链接 → 放行

| **输入** | **预期** |
|:---------|:---------|
| `["share_link_create", "internal_only"]` | `None` |

#### TC-SL-002: 创建公开链接 → 要求确认

| **输入** | **预期** |
|:---------|:---------|
| `["share_link_create", "public_access"]` | `"ask"` |

#### TC-SL-003: 公开链接 + 含敏感内容 → 阻断

| **输入** | **预期** |
|:---------|:---------|
| `["share_link_create", "public_access", "contains_secret"]` | `"block"` |

#### TC-SL-004: 批量创建分享链接 → 升级审批

| **输入** | **预期** |
|:---------|:---------|
| `["share_link_create", "bulk_create"]` | `"escalate"` |

#### TC-SL-005: 修改链接权限从内到外 → 要求确认

| **输入** | **预期** |
|:---------|:---------|
| `["share_link_update", "internal_to_public"]` | `"ask"` |

#### TC-SL-006: 语义增强识别"创建分享链接给外部"

| **输入** | **预期 labels** |
|:---------|:----------------|
| `"给我创建这个文档的分享链接，发给外部客户"` | `"share_link_create"`, `"external_share"` |

---

## 11. P1 场景：云盘资源清理/删除防护

**对应场景**：PO-07（云盘资源清理/删除）
**风险等级**：🔴 高风险
**优先级得分**：16分

### 11.1 测试用例

#### TC-CC-001: 单个文件删除 → 放行

| **输入** | **预期** |
|:---------|:---------|
| `["file_delete", "single_file"]` | `None` |

#### TC-CC-002: 批量删除 < 10 个 → 放行

| **输入** | **预期** |
|:---------|:---------|
| 累积删除 5 次 | `None` |

#### TC-CC-003: 批量删除 10~49 个 → 要求确认

| **输入** | **预期** |
|:---------|:---------|
| 累积删除 15 次 | `"ask"` |

#### TC-CC-004: 批量删除 ≥ 50 个 → 阻断

| **输入** | **预期** |
|:---------|:---------|
| 累积删除 60 次 | `"block"` |

#### TC-CC-005: 删除高价值路径文件 → 要求确认

| **输入** | **预期** |
|:---------|:---------|
| `["file_delete", "high_value_path"]` | `"ask"` |

#### TC-CC-006: 批量删除 + 高价值路径 → 阻断

| **输入** | **预期** |
|:---------|:---------|
| 累积删除 ≥ 10 + 高价值路径 | `"block"` |

#### TC-CC-007: 语义增强识别"清理过期文件"

| **输入** | **预期 labels** |
|:---------|:----------------|
| `"帮我把云盘里 3 个月前的日志清掉"` | `"file_delete"`, `"batch_delete"` |

#### TC-CC-008: 全链路 — 高价值路径批量删除被阻断

| **步骤** | **预期** |
|:---------|:---------|
| RV | `"block"` |

---

## 12. 已覆盖场景回归测试

**对应场景**：SR-05（邮件）、PO-01（日报）、EX-05（附件）
**当前状态**：✅ 已有 5 个场景覆盖

### 12.1 回归用例

| 编号 | 场景 | 输入 | 预期 | 关键验证 |
|:-----|:-----|:-----|:-----|:---------|
| RG-01 | 邮件外发+外部收件人+敏感内容 | `mail_send + external_recipient + contains_secret` | `block` | 阻断 |
| RG-02 | 邮件外发+批量发送 | `mail_send + bulk_send` | `escalate` | 升级 |
| RG-03 | 邮件外发+AI生成内容无审阅 | `mail_send + ai_generated_content` | `ask` | 确认 |
| RG-04 | 日报生成+缺少范围约束 | `report_generate + missing_scope_constraint` | `ask` | 确认 |
| RG-05 | 日报外发+外部收件人+内部来源 | `report_send + external_recipient + internal_source` | `block` | 阻断 |
| RG-06 | 附件下载+外发 | `attachment_download → network_egress` | `escalate` | 升级 |
| RG-07 | 正常邮件内部发送 | `mail_send + internal_recipient` | `None` | 放行 |

### 12.2 回归频率

- 每次 Git 提交前运行回归
- 每次新增监视器后运行全量回归
- 每次修改 `detection.py` 时重点回归

---

## 13. 跨场景链式风险测试

**对应监视器**：SecurityChainMonitor
**核心能力**：多步组合检测

### 13.1 链式模式

| 编号 | 链式模式 | 风险等级 | 涉及场景 |
|:-----|:---------|:---------|:---------|
| CH-01 | 先查敏感表 → 再导出 → 再外传 | 🔴 高危 | DE + BF |
| CH-02 | 先批量收集文件 → 打包 → 外传 | 🔴 高危 | BF + DS |
| CH-03 | 先关闭审计 → 再修改配置 | 🔴 高危 | SC |
| CH-04 | 先下载附件 → 再外发邮件 | 🟡 中危 | EX-05 + EX-07 |
| CH-05 | 先搜索高价值路径 → 再删除 | 🟡 中危 | PO-07 |
| CH-06 | 先导出聊天记录 → 再上传外部 | 🔴 高危 | CE + BF |
| CH-07 | 代码含密钥 → 推送到远程 | 🔴 高危 | CP |
| CH-08 | 代提交审批 → 跳转审批链 → 批量通过 | 🔴 高危 | AD |

### 13.2 测试用例

#### TC-CH-001: 关闭审计 → 修改配置 → 阻断

| **步骤** | **输入 props** |
|:---------|:---------------|
| step1 | `["config_audit_disable"]` |
| step2 | `["config_modify"]` |
| **预期** | step2 返回 `"block"` |

#### TC-CH-002: 下载附件 → 邮件外发 → 升级审批

| **步骤** | **输入 props** |
|:---------|:---------------|
| step1 | `["attachment_download"]` |
| step2 | `["network_egress", "mail_send"]` |
| **预期** | step2 返回 `"escalate"` |

#### TC-CH-003: 查敏感表 → 导出 CSV → 上传外部 → 阻断

| **步骤** | **输入 props** |
|:---------|:---------------|
| step1 | `["database_query", "user_table"]` |
| step2 | `["file_write", "export_format"]` |
| step3 | `["network_egress", "file_upload", "external_target"]` |
| **预期** | step3 返回 `"block"` |

#### TC-CH-004: 链式风险全窗口溢出测试

| 项目 | 内容 |
|:-----|:-----|
| **场景** | 窗口内连续 20 步低风险操作 + 1 步高风险 |
| **预期** | 高风险步触发应有风险评估 |
| **验证点** | 窗口滑动不影响最新事件的风险判定 |

#### TC-CH-005: 链式超过窗口大小后重置

| 项目 | 内容 |
|:-----|:-----|
| **场景** | 先执行 step1（高风险链起手），再执行 15 步无关操作，最后执行 step2（链式收尾） |
| **预期** | step2 不被链式检测（因窗口已滑动） |
| **验证点** | 窗口大小限制正确 |

---

## 14. 语义增强层专项测试

### 14.1 测试维度

| 维度 | 测试点 | 覆盖数 |
|:-----|:-------|:-------|
| 本地模式 | 7 个维度标签提取正确性 | 7 |
| LLM 模式 | API 调用、JSON 解析 | 3 |
| LLM 降级 | 超时/非JSON/网络错误 → 本地回退 | 3 |
| 场景识别 | 5 个办公场景 + 6 个 P0/P1 场景 | 11 |
| 约束提取 | 排除条件、时间范围、作用域 | 4 |
| 空输入/边界 | None、空字符串、纯表情 | 3 |

### 14.2 用例

#### TC-SE-001: 本地模式 — 邮件发送标签

| **输入** | **预期 labels 子集** |
|:---------|:---------------------|
| `"发邮件给 alice@example.com，附上合同"` | `"mail_send"`, `"has_recipient"`, `"contains_attachment"` |

#### TC-SE-002: 本地模式 — 日报发送标签

| **输入** | **预期 labels 子集** |
|:---------|:---------------------|
| `"把昨天的周报发给老板"` | `"report_send"`, `"has_recipient"` |

#### TC-SE-003: 本地模式 — 文件删除标签

| **输入** | **预期 labels 子集** |
|:---------|:---------------------|
| `"删除 /tmp/cache 目录"` | `"file_delete"`, `"path_tmp"` |

#### TC-SE-004: 本地模式 — 网络外发标签

| **输入** | **预期 labels 子集** |
|:---------|:---------------------|
| `"把文件上传到 http://example.com"` | `"network_http"`, `"file_upload"` |

#### TC-SE-005: 本地模式 — 配置修改标签

| **输入** | **预期 labels 子集** |
|:---------|:---------------------|
| `"把 openclaw 的认证关掉"` | `"config_auth_disable"` |

#### TC-SE-006: 本地模式 — 渠道外发标签

| **输入** | **预期 labels 子集** |
|:---------|:---------------------|
| `"在群里发一条公告"` | `"channel_external_send"`, `"bulk_send"` |

#### TC-SE-007: LLM 模式 — 成功路径

| **步骤** | **预期** |
|:---------|:---------|
| 配置 API key → 调用 `evaluate()` → LLM 返回有效 JSON | `engine` 字段为 `"llm-deepseek-chat"` |

#### TC-SE-008: LLM 模式 — 超时降级

| **步骤** | **预期** |
|:---------|:---------|
| LLM 调用超时 → 自动降级 | `engine` 字段为 `"builtin-fallback"` |

#### TC-SE-009: LLM 模式 — 非 JSON 返回降级

| **步骤** | **预期** |
|:---------|:---------|
| LLM 返回非 JSON 文本 → 自动降级 | `engine` 字段为 `"builtin-fallback"` |

#### TC-SE-010: 空输入处理

| **输入** | **预期** |
|:---------|:---------|
| `""` (空字符串) | 不抛异常，返回有效语义结构 |
| `None` | 不抛异常，返回有效语义结构 |
| `"😂👍"` (纯表情) | 不抛异常，低 confidence |

---

## 15. 白名单与审计专项测试

### 15.1 白名单测试

#### TC-WL-001: 路径白名单匹配

| **输入** | **预期** |
|:---------|:---------|
| `target_paths=["/tmp/openclaw-case.txt"]` | 匹配 `file:/tmp/` 路径规则 |

#### TC-WL-002: 网络白名单匹配

| **输入** | **预期** |
|:---------|:---------|
| `network_targets=["http://127.0.0.1:19001"]` | 匹配 `network:127.0.0.1` 规则 |

#### TC-WL-003: 命令白名单匹配

| **输入** | **预期** |
|:---------|:---------|
| `command="cat /tmp/file.txt"` | 匹配 `command:cat` 规则 |

#### TC-WL-004: 白名单未命中 → 进入 RV

| **输入** | **预期** |
|:---------|:---------|
| 路径/网络/命令均不在白名单 | `matches` 为空，进入检测流程 |

#### TC-WL-005: 白名单 + 高风险叠加

| **输入** | **预期** |
|:---------|:---------|
| 路径在白名单但含 `contains_secret` 标签 | 敏感标签优先，仍触发 RV |

### 15.2 审计测试

#### TC-AU-001: 审计链完整性

| **步骤** | **预期** |
|:---------|:---------|
| 追加 3 条记录 | `verify_chain()` 返回 `ok=True` |

#### TC-AU-002: 审计链被篡改

| **步骤** | **预期** |
|:---------|:---------|
| 直接修改已写入的审计记录 | `verify_chain()` 返回 `ok=False` |

#### TC-AU-003: 导出格式覆盖

| **步骤** | **预期** |
|:---------|:---------|
| `export()` | JSON + CSV 文件均生成且在正确路径 |

#### TC-AU-004: 查询顺序稳定

| **项目** | **内容** |
|:---------|:---------|
| **场景** | 同一时间戳的多条记录，查询时按插入顺序逆序 |
| **预期** | `query()` 最新在前，插入顺序在逆序中保持 |

#### TC-AU-005: 审计含完整语义元数据

| **项目** | **内容** |
|:---------|:---------|
| **输入** | 发送包含语义标签的事件 |
| **预期** | 审计记录中包含 `metadata.semantic` 和 `metadata.rv_trace` |

---

## 16. 前端契约测试

### 16.1 契约检查项

| 编号 | 契约 | 测试点 |
|:-----|:-----|:-------|
| FC-01 | 决策结果含 Pipeline Timings | `semantic_ms` / `detection_ms` / `rv_ms` / `controller_ms` / `total_ms` |
| FC-02 | Summary 不暴露敏感信息 | 无 `appSecret`/`token`/`raw` 字段 |
| FC-03 | 状态枚举一致性 | `pending_approval` / `approved` / `blocked` / `allowed` |
| FC-04 | 前端可消费 RV 结果 | `rv_verdict` 字段存在且为 `ok/ask/block/escalate` |
| FC-05 | 前端可消费语义元数据 | `metadata.semantic.scenario` 存在且可读 |

---

## 17. 基线扫描测试

### 17.1 测试用例

#### TC-BL-001: 基线报告生成完整性

| **项目** | **内容** |
|:---------|:---------|
| **输入** | 标准配置目录 |
| **预期** | 输出 JSON / HTML / PDF / fix_script, checks 列表非空 |

#### TC-BL-002: 修复脚本正确引用路径

| **项目** | **内容** |
|:---------|:---------|
| **输入** | 配置目录含空格 |
| **预期** | fix_script 使用 `shlex.quote()` 引用路径 |

#### TC-BL-003: 基线不误报当前端口

| **项目** | **内容** |
|:---------|:---------|
| **输入** | gateway port=18789 |
| **预期** | 该端口不被标记为额外开放端口 |

#### TC-BL-004: 基线检测发现

| 检查项 | 检测条件 | 预期 finding_id |
|:-------|:---------|:----------------|
| 配置权限 | config 文件权限非 600 | BASE-002 |
| 以 root 运行 | 检测用户为 root | BASE-003 |
| 额外监听端口 | 除 gateway 外有监听端口 | BASE-004 |
| 无效权限检查 | 不存在的路径 | 无错误异常 |

---

## 18. 异常与边界测试

### 18.1 异常测试

| 编号 | 场景 | 输入 | 预期行为 |
|:-----|:-----|:-----|:---------|
| EXC-01 | 无效 action_type | `"invalid_type"` | 降级到 `ask`，不抛异常 |
| EXC-02 | 空 props | `[]` | 正常处理，放行 |
| EXC-03 | 特大窗口 | 窗口大小设置为 10000 | 不 OOM，性能可接受 |
| EXC-04 | 恶意构造 props | `["block"]` 标签伪造 | 标签必须来源于语义层 |
| EXC-05 | 重复事件风暴 | 1秒内 1000 个事件 | 不 OOM，正确维持窗口 |
| EXC-06 | 事件类型缺失 | event 字段缺失 | 降级到 fallback 决策 |
| EXC-07 | 长时间无事件 | 10 分钟无事件后触发 | 窗口正确过期 |

### 18.2 边界测试

| 编号 | 边界条件 | 测试值 | 预期 |
|:-----|:---------|:-------|:-----|
| BND-01 | 批量删除阈值下限 | 9 → 10 个 | `None` → `"ask"` |
| BND-02 | 批量删除阈值上限 | 49 → 50 个 | `"ask"` → `"block"` |
| BND-03 | 窗口大小边界 | max_size=5，push 第6个 | 窗口正确丢弃最旧事件 |
| BND-04 | 链式检测窗口 | 精确 5 步内有前序事件 | 正确匹配 |
| BND-05 | 链式检测窗口 +1 | 6 步前的前序事件 | 不匹配 |

---

## 19. 性能与降级测试

### 19.1 性能测试

| 编号 | 测试点 | 方法 | 阈值 |
|:-----|:-------|:-----|:-----|
| PERF-01 | 本地语义增强延迟 | 调用 1000 次取 P99 | `< 5ms` |
| PERF-02 | DetectionEngine 规则匹配延迟 | 全规则集匹配 1000 次取 P99 | `< 10ms` |
| PERF-03 | WindowManager push 延迟 | push 10000 次取 P99 | `< 1ms` |
| PERF-04 | RV Engine 全监视器评估延迟 | 全监视器评估 1000 次取 P99 | `< 5ms` |
| PERF-05 | 全链路延迟（不含 LLM） | 输入到决策输出 | `< 20ms` |
| PERF-06 | 全链路延迟（含 LLM 模式） | 输入到决策输出 | `< 600ms` |

> 已落地实现：`tests/test_perf_smoke.py`（2026-08-14）覆盖约束引擎/RV 引擎/会话状态冒烟基准（本机实测 0.07ms/0.08ms/0.75ms，宽松阈值 50ms，纳入全量回归）。

### 19.2 降级测试

| 编号 | 降级场景 | 触发条件 | 预期行为 |
|:-----|:---------|:---------|:---------|
| DGR-01 | LLM API 不可用 | 超时 > 10s | 回退到本地规则化 |
| DGR-02 | LLM 返回乱码 | 非 JSON 内容 | 记审计 + 回退本地 |
| DGR-03 | LLM 置信度低 | confidence < 0.3 | 仅辅助，不替代规则 |
| DGR-04 | 语义层内存不足 | MemoryError | 降级到纯规则引擎 |
| DGR-05 | RV 引擎异常 | 监视器内部异常 | 降级到保守 `ask` |

---

## 20. 测试实现指南

### 20.1 项目结构

```text
OpenClaw-RVGuarder/
├── tests/
│   ├── test_detection.py             # 检测引擎 (47条规则)
│   ├── test_semantic_enhancer.py     # 语义增强 (5场景 + LLM)
│   ├── test_rv.py                    # RV引擎 + 6监视器
│   ├── test_whitelist_audit.py       # 白名单 + 审计
│   ├── test_baseline.py              # 基线扫描
│   ├── test_frontend_rv_contract.py  # 前端契约
│   ├── test_web_cli.py               # Web CLI
│   │
│   ├── scenarios/                    # ★ 场景测试（新增）
│   │   ├── test_scenario_broadcast.py      # P0: 消息群发
│   │   ├── test_scenario_data_export.py    # P0: 数据导出
│   │   ├── test_scenario_batch_file.py     # P0: 文件批量操作
│   │   ├── test_scenario_doc_share.py      # P1: 文档分享
│   │   ├── test_scenario_chat_export.py    # P1: 聊天记录导出
│   │   ├── test_scenario_approve_delegate.py # P1: 代提交审批
│   │   ├── test_scenario_code_push.py      # P1: 代码推送
│   │   ├── test_scenario_share_link.py     # P1: 共享链接
│   │   ├── test_scenario_cloud_cleanup.py  # P1: 云盘清理
│   │   └── test_scenario_chain.py          # 链式风险
│   │
│   └── __init__.py
│
├── e2e/                               # E2E 测试
│   ├── test_broadcast_flow.py         # 群发完整事务
│   ├── test_data_export_flow.py       # 数据导出完整事务
│   └── test_batch_file_flow.py        # 文件批量操作完整事务
│
└── conftest.py                        # ★ Pytest fixtures（可选）
```

### 20.2 推荐测试框架

- **现有**：`unittest`（项目已有）
- **推荐**：保持 `unittest` + 考虑引入 `pytest` 用于参化测试
- **Mock**：`unittest.mock`（已有）
- **临时目录**：`tempfile.TemporaryDirectory`（已有）

### 20.3 编写规范

```python
# 1. 每个场景测试文件一个 TestCase 类
class TestBroadcastScenario(unittest.TestCase):
    """P0-EX-10: 消息群发/广播防护 — 全场景测试。"""

    def setUp(self):
        self.monitor = BroadcastMonitor()
        self.wm = WindowManager()

    # 2. 方法命名: test_{条件}_{预期}
    def test_broadcast_with_external_recipient_expects_block(self):
        step = {"event": "channel_send", "props": [
            "channel_send", "bulk_send", "external_recipient", "cross_org",
        ]}
        self.wm.push(step)
        result = self.monitor.feed(step, self.wm)
        self.assertEqual(result, "block")

    # 3. 每个方法只测一个行为
    def test_broadcast_default_ask(self):
        step = {"event": "channel_send", "props": [
            "channel_send", "bulk_send",
        ]}
        self.wm.push(step)
        result = self.monitor.feed(step, self.wm)
        self.assertEqual(result, "ask")

    # 4. 使用 docstring 记录场景编号
    def test_single_chat_ok(self):
        """EX-10变体: 单聊消息不触发群发保护。"""
        step = {"event": "channel_send", "props": ["channel_send"]}
        self.wm.push(step)
        result = self.monitor.feed(step, self.wm)
        self.assertIsNone(result)


# 5. 语义增强场景测试
class TestBroadcastSemanticScenario(unittest.TestCase):
    """P0-EX-10: 语义增强层群发标签提取测试。"""

    def test_semantic_identifies_bulk_send(self):
        result = SemanticEnhancer().evaluate(
            BehaviorEvent(..., raw_user_intent="通知全员明天下午开会"),
            {"source_message": "通知全员明天下午开会", "origin": "chat"},
        )
        self.assertIn("bulk_send", result["semantic"]["labels"])
        self.assertIn("channel_send", result["semantic"]["labels"])
```

### 20.4 现有测试扩展建议

| 现有文件 | 需新增测试 | 优先级 |
|:---------|:-----------|:-------|
| `test_detection.py` | P0 场景规则命中测试 | P0 |
| `test_semantic_enhancer.py` | P0/P1 场景标签提取测试 | P0 |
| `test_rv.py` | Broadcast/DataExport/BatchFile 集成测试 | P0 |
| `test_whitelist_audit.py` | 白名单与场景决策的互斥测试 | P1 |
| `test_frontend_rv_contract.py` | 新增场景的 Timings 覆盖 | P1 |

### 20.5 新增标签注册

在 `semantic_enhancer.py` 新增语义标签：

```python
# P0 场景标签
BROADCAST_LABELS = ["channel_send", "bulk_send", "cross_org",
                    "external_recipient", "broadcast_message"]
DATA_LABELS = ["database_query", "export_format", "batch_export",
               "large_export", "user_table", "payment_data"]
FILE_BATCH_LABELS = ["file_compress", "file_package", "share_link_update",
                     "public_access", "external_target", "batch_file_upload"]

# P1 场景标签
DOC_SHARE_LABELS = ["doc_share", "internal_share", "external_share"]
CHAT_EXPORT_LABELS = ["chat_export", "self_chat", "group_chat"]
APPROVE_DELEGATE_LABELS = ["approval_delegate", "delegate_submit",
                           "skip_chain", "batch_submit"]
CODE_PUSH_LABELS = ["code_commit", "git_push", "contains_credential",
                    "sensitive_file", "remote_origin"]
SHARE_LINK_LABELS = ["share_link_create", "share_link_update",
                     "internal_to_public"]
CLOUD_CLEANUP_LABELS = ["file_delete", "batch_delete", "high_value_path"]
```

### 20.6 测试执行

```bash
# 运行全部测试
python -m pytest tests/

# 运行某个场景文件
python -m pytest tests/scenarios/test_scenario_broadcast.py -v

# 运行全部场景测试
python -m pytest tests/scenarios/ -v

# 运行 E2E 测试
python -m pytest e2e/ -v

# 运行并生成覆盖率
python -m pytest tests/ --cov=openclaw_guard --cov-report=html

# 运行性能测试（用 unittest）
python -m unittest tests.test_performance -v
```

---

## 附：测试优先级矩阵

```text
          影响范围
         小     中     大
  高  ┌──────┬──────┬──────┐
      │单元  │场景  │链式  │  ← 先做
  优  │      │      │E2E   │
  先  ├──────┼──────┼──────┤
  级  │边界  │性能  │安全  │
      │异常  │      │渗透  │
  低  ├──────┼──────┼──────┤
      │UI    │文档  │      │  ← 后做
      │      │      │      │
      └──────┴──────┴──────┘
```

**实施顺序建议**：

1. **阶段一（本迭代）**：P0 场景单元测试（Broadcast/DataExport/BatchFile）
2. **阶段二（本迭代）**：P0 场景全链路测试（Manager + RV + Decision）
3. **阶段三（本迭代）**：P0 语义增强标签测试
4. **阶段四（下迭代）**：P1 场景全量测试
5. **阶段五（下迭代）**：链式风险 + E2E 测试
6. **持续**：性能测试、边界测试、异常测试

---

*本测试设计方案覆盖 63 个办公场景中需 RV 保护的 36 个场景，共约 130+ 个测试用例。*
*配合 docs/semantic/office-scenario-matrix.md 使用。*
