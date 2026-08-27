# 个人办公全场景梳理与安全防护目标筛选

**日期**：2026-07-15  
**分析目标**：围绕 OpenClaw AI 助手在个人办公中的全部潜在场景，按流程阶段系统梳理，并筛选本项目需覆盖的目标场景。

---

## 一、概述

### 1.1 分析范围

以"知识工作者个人办公全流程"为视角，覆盖从**事前筹备 → 事中执行 → 事后复盘**三个阶段的全部高频场景。

### 1.2 筛选标准

本项目作为 OpenClaw 安全插件，只应覆盖 **有安全风险、需要拦截/审批/审计的办公场景**。筛选原则：

| 维度 | 要求 |
|:---|:---|
| **安全风险** | 该场景是否涉及数据外发、权限变更、文件删除、配置修改等风险 |
| **自动化程度** | AI 是否可能在无用户确认下执行操作 |
| **合规要求** | 操作是否需留痕、溯源、审批 |
| **用户可见性** | 用户是否能感知到操作正在发生 |

**低风险场景**（如纯查询、纯阅读）→ 不纳入 RV 保护范围，由语义层直接放行。

---

## 二、事前筹备阶段

### 2.1 场景全景

```text
事前筹备
├── 日程规划
│   ├── SR-01 日程查询与安排       🟢 低风险
│   ├── SR-02 多方忙闲协调邀约     🟡 中风险
│   └── SR-03 批量创建/修改日历   🔴 高风险
├── 会议管理
│   ├── SR-04 会议预约与通知        🟡 中风险
│   ├── SR-05 会议资料准备与分发    🔴 高风险
│   ├── SR-06 会议纪要自动生成      🟢 低风险
│   └── SR-07 录制/转录权限变更    🔴 高风险
├── 差旅申请
│   ├── SR-08 差旅申请提交          🟡 中风险
│   ├── SR-09 机票/酒店预订         🔴 高风险
│   ├── SR-10 费用预估与提交        🟡 中风险
│   └── SR-11 行程变更/取消         🔴 高风险
├── 资源协调
│   ├── SR-12 会议室资源预定        🟡 中风险
│   ├── SR-13 设备借用申请          🟢 低风险
│   └── SR-14 跨部门资源协调外发    🔴 高风险
└── 信息收集
    ├── SR-15 网络资料检索          🟢 低风险
    ├── SR-16 引用/转载敏感信息     🔴 高风险
    └── SR-17 竞品信息搜集          🟡 中风险
```

### 2.2 各场景详表

| 编号 | 场景 | 核心需求 | 使用频率 | 目标用户 | 安全风险 | 需RV？ |
|:---|:---|:---|:---|:---|:---|:---|
| SR-01 | 日程查询与安排 | 查空闲时间、创建日程 | 每日 | 全员 | 🟢 只读查询 | ❌ |
| SR-02 | 多方忙闲协调邀约 | 查多人日历、发送邀请 | 每周 | 管理者/PM | 🟡 自动发送邀请可能打扰他人 | ❌ |
| SR-03 | 批量创建/修改日历 | 导入CSV批量创建、修改已有日程 | 每月 | 行政/助理 | 🔴 覆盖已有安排、删除重要日程 | ✅ |
| SR-04 | 会议预约与通知 | 预约会议、发送通知链接 | 每日 | 全员 | 🟡 可能误发给外部与会者 | ❌ |
| SR-05 | 会议资料准备与分发 | 收集资料、生成文档、外发参会人 | 每周 | 全员 | 🔴 内部资料外泄风险 | ✅ |
| SR-06 | 会议纪要自动生成 | 转录→摘要→结构化 | 每周 | 全员 | 🟢 内容不外发 | ❌ |
| SR-07 | 录制/转录权限变更 | 谁可以查看/下载 | 偶尔 | 组织者 | 🔴 权限泄露导致敏感信息扩散 | ✅ |
| SR-08 | 差旅申请提交 | 填申请表、提交审批 | 每月 | 全员 | 🟡 含个人信息 | ❌ |
| SR-09 | 机票/酒店预订 | 用公司账号预订 | 每月 | 全员 | 🔴 涉及公司支付账户 | ✅ |
| SR-10 | 费用预估与提交 | 估算差旅费用并提报 | 每月 | 全员 | 🟡 含财务数据 | ❌ |
| SR-11 | 行程变更/取消 | 改签/退票/取消住宿 | 偶尔 | 全员 | 🔴 可能产生违约金 | ✅ |
| SR-12 | 会议室资源预定 | 查空闲、预约 | 每日 | 全员 | 🟢 无实质风险 | ❌ |
| SR-13 | 设备借用申请 | 申请设备、登记归还 | 每周 | 全员 | 🟢 低风险 | ❌ |
| SR-14 | 跨部门资源协调外发 | 向外部人员发资料 | 每周 | 全员 | 🔴 内部数据外泄 | ✅ |
| SR-15 | 网络资料检索 | 搜索、摘要、整理 | 每日 | 全员 | 🟢 只读 | ❌ |
| SR-16 | 引用/转载敏感信息 | 将外部文章内容转载到内部 | 每周 | 全员 | 🔴 版权风险、恶意内容传播 | ✅ |
| SR-17 | 竞品信息搜集 | 爬取竞品信息汇总 | 每月 | 市场/产品 | 🟡 法律边界 | ❌ |

---

## 三、事中执行阶段

### 3.1 场景全景

```text
事中执行
├── 任务与项目管理
│   ├── EX-01 任务创建与指派        🟡 中风险
│   ├── EX-02 任务进度批量更新      🟡 中风险
│   ├── EX-03 截止日期批量修改      🔴 高风险
│   └── EX-04 项目成员权限管理      🔴 高风险
├── 文档协作
│   ├── EX-05 文档编辑与保存        🟡 中风险
│   ├── EX-06 版本管理与恢复        🔴 高风险
│   ├── EX-07 文档分享与外发        🔴 高风险
│   ├── EX-08 批注/评论清理         🟡 中风险
│   └── EX-09 文档格式转换/导出     🟡 中风险
├── 即时通讯
│   ├── EX-10 消息群发/广播         🔴 高风险
│   ├── EX-11 文件分享到群聊        🔴 高风险
│   ├── EX-12 自动回复设置          🟡 中风险
│   ├── EX-13 聊天记录导出          🔴 高风险
│   └── EX-14 消息撤回/修改         🟡 中风险
├── 审批流程
│   ├── EX-15 代提交审批            🔴 高风险
│   ├── EX-16 批量审批/拒绝         🔴 高风险
│   ├── EX-17 审批意见自动生成      🟡 中风险
│   └── EX-18 审批链路跳转          🔴 高风险
├── 数据处理
│   ├── EX-19 数据库查询与导出      🔴 高风险
│   ├── EX-20 批量数据导入/更新     🔴 高风险
│   ├── EX-21 数据脱敏/匿名化       🟡 中风险
│   └── EX-22 报表生成与外发        🔴 高风险
├── 代码开发
│   ├── EX-23 代码读写              🟢 低风险
│   ├── EX-24 代码提交与推送        🔴 高风险
│   ├── EX-25 代码审查自动回复      🟡 中风险
│   └── EX-26 密钥/令牌操作         🔴 高风险
└── 云端操作
    ├── EX-27 文件批量上传/下载      🔴 高风险
    ├── EX-28 共享链接生成/修改      🔴 高风险
    └── EX-29 权限批量变更           🔴 高风险
```

### 3.2 各场景详表

| 编号 | 场景 | 核心需求 | 使用频率 | 用户群体 | 安全风险 | 需RV？ |
|:---|:---|:---|:---|:---|:---|:---|
| EX-01 | 任务创建与指派 | 创建任务、设置负责人/DDL | 每日 | 全员 | 🟡 错误指派导致混乱 | ❌ |
| EX-02 | 任务进度批量更新 | 批量标记完成/延期 | 每周 | 全员 | 🟡 更新错误 | ❌ |
| EX-03 | 截止日期批量修改 | 统一延期、调整里程碑 | 每月 | 管理者 | 🔴 关键节点变更未通知相关人员 | ✅ |
| EX-04 | 项目成员权限管理 | 添加/移除成员、变更角色 | 每周 | 管理者 | 🔴 权限越级、数据泄露 | ✅ |
| EX-05 | 文档编辑与保存 | 增删改内容 | 每日 | 全员 | 🟡 误删、格式错乱 | ❌ |
| EX-06 | 版本管理与恢复 | 查看历史版本、回滚 | 每周 | 全员 | 🔴 回滚导致数据丢失 | ✅ |
| EX-07 | 文档分享与外发 | 生成分享链接、设置权限 | 每日 | 全员 | 🔴 内部文档意外外泄 | ✅ |
| EX-08 | 批注/评论清理 | 批量删除/归档批注 | 每周 | 全员 | 🟡 审计追溯丢失 | ❌ |
| EX-09 | 文档格式转换/导出 | PDF/Word/HTML互转 | 每日 | 全员 | 🟡 转换后格式泄露 | ❌ |
| EX-10 | 消息群发/广播 | 全员通知、频道广播 | 每周 | 行政/HR | 🔴 错误信息扩散、无法撤回 | ✅ |
| EX-11 | 文件分享到群聊 | 发文件到群聊/频道 | 每日 | 全员 | 🔴 敏感文件发错群 | ✅ |
| EX-12 | 自动回复设置 | 设置/修改自动回复规则 | 每月 | 全员 | 🟡 泄露个人状态信息 | ❌ |
| EX-13 | 聊天记录导出 | 导出群聊/私聊记录 | 每月 | 全员 | 🔴 隐私泄露、合规风险 | ✅ |
| EX-14 | 消息撤回/修改 | 撤回已发送消息 | 偶尔 | 全员 | 🟡 可接受 | ❌ |
| EX-15 | 代提交审批 | 代他人提交审批单 | 每周 | 助理/代理 | 🔴 冒名提交、越权审批 | ✅ |
| EX-16 | 批量审批/拒绝 | 批量同意/拒绝待审批项 | 每周 | 管理者 | 🔴 批量操作遗漏重要审批 | ✅ |
| EX-17 | 审批意见自动生成 | AI生成审批结论 | 每周 | 全员 | 🟡 意见不准确 | ❌ |
| EX-18 | 审批链路跳转 | 跳过审批人、加签/转审 | 偶尔 | 管理者 | 🔴 绕过审批链 | ✅ |
| EX-19 | 数据库查询与导出 | SQL查询、导出结果 | 每日 | 技术人员 | 🔴 敏感数据批量导出 | ✅ |
| EX-20 | 批量数据导入/更新 | 导入CSV更新数据 | 每周 | 运营/分析师 | 🔴 脏数据覆盖、数据不一致 | ✅ |
| EX-21 | 数据脱敏/匿名化 | 对敏感数据脱敏 | 每周 | 安全/合规 | 🟡 脱敏不彻底 | ❌ |
| EX-22 | 报表生成与外发 | 生成报表并发送 | 每周 | 全员 | 🔴 未经确认的报表外发 | ✅ |
| EX-23 | 代码读写 | 查看/修改代码 | 每日 | 开发 | 🟢 读操作安全 | ❌ |
| EX-24 | 代码提交与推送 | commit/push到远程 | 每日 | 开发 | 🔴 密钥硬编码、误提交敏感文件 | ✅ |
| EX-25 | 代码审查自动回复 | AI生成CR评论 | 每周 | 开发 | 🟡 错误建议 | ❌ |
| EX-26 | 密钥/令牌操作 | 生成/撤销API密钥 | 每月 | 开发者 | 🔴 密钥泄露、服务中断 | ✅ |
| EX-27 | 文件批量上传/下载 | 批量操作云盘文件 | 每日 | 全员 | 🔴 大量内部文件外流 | ✅ |
| EX-28 | 共享链接生成/修改 | 创建/修改分享链接权限 | 每日 | 全员 | 🔴 公开分享未授权内容 | ✅ |
| EX-29 | 权限批量变更 | 批量修改文件/文件夹权限 | 每周 | 全员 | 🔴 权限过度开放 | ✅ |

---

## 四、事后复盘阶段

### 4.1 场景全景

```text
事后复盘
├── 工作总结
│   ├── PO-01 周报/月报自动生成     🟡 中风险
│   ├── PO-02 绩效数据汇总          🟡 中风险
│   ├── PO-03 KPI/OKR进度更新      🔴 高风险
│   └── PO-04 工作总结外发          🔴 高风险
├── 项目归档
│   ├── PO-05 项目文档归档          🟡 中风险
│   ├── PO-06 代码仓库归档/删除     🔴 高风险
│   ├── PO-07 云盘资源清理/删除     🔴 高风险
│   └── PO-08 项目资产移交          🔴 高风险
├── 知识沉淀
│   ├── PO-09 经验文档整理与发布    🟡 中风险
│   ├── PO-10 最佳实践内部共享      🟡 中风险
│   └── PO-11 敏感经验脱敏分享      🟡 中风险
├── 审计追踪
│   ├── PO-12 操作审计导出          🔴 高风险
│   ├── PO-13 日志归档              🟡 中风险
│   └── PO-14 合规报告生成          🟡 中风险
└── 反馈迭代
    ├── PO-15 匿名反馈收集          🟢 低风险
    ├── PO-16 问题跟踪与升级        🟡 中风险
    └── PO-17 对外反馈发布          🔴 高风险
```

### 4.2 各场景详表

| 编号 | 场景 | 核心需求 | 使用频率 | 用户群体 | 安全风险 | 需RV？ |
|:---|:---|:---|:---|:---|:---|:---|
| PO-01 | 周报/月报自动生成 | 汇总数据、生成报告 | 每周 | 全员 | 🟡 含未公开数据 | ❌ |
| PO-02 | 绩效数据汇总 | 收集各系统数据、汇总 | 每月 | 全员 | 🟡 个人隐私数据 | ❌ |
| PO-03 | KPI/OKR进度更新 | 标记完成度、更新状态 | 每月 | 全员 | 🔴 数据造假风险 | ✅ |
| PO-04 | 工作总结外发 | 工作汇报发邮件/PPT | 每周 | 全员 | 🔴 内部绩效数据外泄 | ✅ |
| PO-05 | 项目文档归档 | 整理文档、存归档库 | 每季度 | 全员 | 🟡 误归档案 | ❌ |
| PO-06 | 代码仓库归档/删除 | 归档旧仓库、清理 | 每季度 | 开发 | 🔴 误删重要仓库 | ✅ |
| PO-07 | 云盘资源清理/删除 | 批量清理过期文件 | 每月 | 全员 | 🔴 误删未备份文件 | ✅ |
| PO-08 | 项目资产移交 | 交接文档/账号/资源给接替者 | 每季度 | 全员 | 🔴 敏感凭证直接暴露给接替者外的范围 | ✅ |
| PO-09 | 经验文档整理与发布 | 将项目经验整理为内部文档 | 每月 | 全员 | 🟡 含未公开信息 | ❌ |
| PO-10 | 最佳实践内部共享 | 将经验分享给团队 | 每月 | 全员 | 🟡 内部范围低风险 | ❌ |
| PO-11 | 敏感经验脱敏分享 | 脱敏后分享 | 偶尔 | 全员 | 🟡 脱敏不彻底风险 | ❌ |
| PO-12 | 操作审计导出 | 导出个人/团队审计日志 | 每月 | 全员 | 🔴 审计数据泄露 | ✅ |
| PO-13 | 日志归档 | 系统日志转存储 | 自动 | 运维 | 🟡 日志含敏感信息 | ❌ |
| PO-14 | 合规报告生成 | 生成合规检查报告 | 每月 | 合规 | 🟡 报告含内部发现 | ❌ |
| PO-15 | 匿名反馈收集 | 收集匿名意见 | 每月 | 全员 | 🟢 无风险 | ❌ |
| PO-16 | 问题跟踪与升级 | 创建问题、分配处理人 | 每日 | 全员 | 🟡 错误分类 | ❌ |
| PO-17 | 对外反馈发布 | 将反馈公之于众 | 每周 | 社区/客服 | 🔴 内部信息外泄 | ✅ |

---

## 五、场景汇总统计

### 5.1 全场景分布

| 阶段 | 总场景数 | 高风险数 | 中风险数 | 低风险数 | 需RV数 |
|:---|:---|:---|:---|:---|:---|
| 事前筹备 | 17 | 8 | 5 | 4 | **8** |
| 事中执行 | 29 | 20 | 7 | 2 | **20** |
| 事后复盘 | 17 | 8 | 8 | 1 | **8** |
| **合计** | **63** | **36** | **20** | **7** | **36** |

### 5.2 已覆盖 vs 未覆盖

| 状态 | 场景数 | 说明 |
|:---|:---|:---|
| 当前已覆盖（未接入前已有规则） | 5 | mail_send, mail_read, report_generate, report_send, attachment_download |
| 需新增 RV 保护 | 31 | 见下方筛选结果 |
| 低风险（无需纳入） | 27 | 纯查询/只读/无外发操作 |

---

## 六、优先级筛选

### 6.1 筛选矩阵

从四个维度打分（1~5），总分决定优先级：

| 维度 | 说明 |
|:---|:---|
| **风险严重度** | 数据泄露/权限失控/合规处罚的潜在损失 |
| **发生频率** | 普通用户每周使用次数 |
| **AI自动化程度** | AI能否独立完成（无需用户逐步骤确认） |
| **链式风险** | 是否容易被恶意利用组合成攻击链 |

### 6.2 P0（立即纳入，3个场景）

| 编号 | 场景 | 风险 | 频率 | AI自动化 | 链式 | 总分 | 当前状态 |
|:---|:---|:---|:---|:---|:---|:---|:---|
| EX-10 | 消息群发/广播 | 5 | 4 | 5 | 3 | **17** | ❌ 未覆盖 |
| EX-19 | 数据库查询与导出 | 5 | 4 | 4 | 5 | **18** | ❌ 未覆盖 |
| EX-27 | 文件批量上传/下载 | 5 | 5 | 4 | 5 | **19** | ❌ 未覆盖 |

**理由**：
- **消息群发**：AI 一句话就能触发全公司通知，误操作影响面极大，且无法撤回
- **数据库导出**：SQL 查询+导出CSV 两步操作即可将全量用户数据带出，是数据泄露最高频入口
- **文件批量操作**：AI 可以"把文件夹所有文件上传到共享链接"一句话完成，批量数据泄露

### 6.3 P1（第二阶段，6个场景）

| 编号 | 场景 | 风险 | 频率 | AI自动化 | 链式 | 总分 | 当前状态 |
|:---|:---|:---|:---|:---|:---|:---|:---|
| EX-07 | 文档分享与外发 | 5 | 5 | 4 | 3 | **17** | ❌ 未覆盖 |
| EX-13 | 聊天记录导出 | 5 | 3 | 5 | 3 | **16** | ❌ 未覆盖 |
| EX-15 | 代提交审批 | 5 | 3 | 5 | 4 | **17** | ❌ 未覆盖 |
| EX-24 | 代码提交与推送 | 4 | 5 | 4 | 4 | **17** | ❌ 未覆盖 |
| EX-28 | 共享链接生成/修改 | 5 | 5 | 5 | 2 | **17** | ❌ 未覆盖 |
| PO-07 | 云盘资源清理/删除 | 5 | 3 | 5 | 3 | **16** | ❌ 未覆盖 |

### 6.4 P2（第三阶段，其余高风险场景）

剩余 22 个高风险场景按需逐步纳入，此处不再逐一展开。

---

## 七、场景到 RV 规则的映射

### 7.1 P0 场景具体化

#### P0-1：消息群发/广播防护

```python
class BroadcastMonitor(BaseMonitor):
    """消息群发安全监视器。

    FSM:
      idle → single_chat（单聊，安全）
      idle → broadcast（群发/广播，需审批）
      broadcast → blocked（群发含外部收件人/敏感内容）
      broadcast → need_approval（群发前先确认清单）
    """

    states = ["idle", "single_chat", "broadcast", "blocked", "need_approval"]

    def __init__(self):
        self.machine = Machine(model=self, states=self.states, initial="idle")
        self.machine.add_transition("to_single", "*", "single_chat",
            conditions=["is_single_message"])
        self.machine.add_transition("to_broadcast", "*", "broadcast",
            conditions=["is_broadcast"])
        self.machine.add_transition("block_bc", "broadcast", "blocked",
            conditions=["has_external_member"])
        self.machine.add_transition("ask_bc", "broadcast", "need_approval",
            conditions=["needs_approval"])
        self._props: set[str] = set()

    def is_broadcast(self):
        return "channel_send" in self._props and "bulk_send" in self._props

    def is_single_message(self):
        return not self.is_broadcast()

    def has_external_member(self):
        return "external_recipient" in self._props or "cross_org" in self._props

    def needs_approval(self):
        return "contains_secret" in self._props or "contains_attachment" in self._props

    def feed(self, step, window):
        self._props = set(step.get("props", []))
        event = step.get("event", "")
        if "channel_send" not in self._props and "network_egress" not in self._props:
            return None

        if self.is_broadcast():
            self.to_broadcast()
            if self.has_external_member():
                self.block_bc()
                return "block"
            if self.needs_approval():
                self.ask_bc()
                return "ask"
            return "ask"  # 群发默认需要审批

        return None
```

#### P0-2：数据库查询与导出防护

```python
class DataExportMonitor(BaseMonitor):
    """数据库查询与导出安全监视器。

    关键 RV 规则：
    - 查询后立即导出 → escalate
    - 导出行数超过阈值 → block
    - 查询敏感表（user, payment, credential）→ ask
    """

    def feed(self, step, window):
        props = set(step.get("props", []))
        event = step.get("event", "")

        if "database_query" in props:
            # 检查查询对象是否为敏感表
            if any(t in str(props) for t in ["user_table", "payment", "credential"]):
                return "ask"

            # 多步模式：查询后文件写入（导出）
            if "file_write" in props and "export_format" in props:
                if window.contains_any({"database_query"}, window_size=3):
                    return "escalate"

            return None

        if "file_write" in props and "export" in str(props):
            # 检查是否是批量导出
            if "batch_export" in props or "large_export" in props:
                return "block"
            if window.contains_any({"database_query"}, window_size=5):
                return "ask"

        return None
```

#### P0-3：文件批量操作防护

```python
class BatchFileMonitor(BaseMonitor):
    """文件批量操作安全监视器。

    关键 RV 规则：
    - 批量上传外部 → escalate
    - 批量删除（超过阈值）→ ask
    - 共享链接更改权限 → ask
    - "下载→压缩→外发"三步骤链 → block
    """

    def feed(self, step, window):
        props = set(step.get("props", []))

        # 多步链：收集文件 → 打包 → 外传
        if "network_egress" in props or "file_upload" in props:
            if window.sequence_matches([
                {"file_search", "file_read"},
                {"file_compress", "file_package"},
            ], window_size=10):
                return "block"

        # 批量删除
        if "file_delete" in props:
            delete_count = window.cumulative_count("file_delete", window_size=20)
            if delete_count >= 10:
                return "ask"
            if delete_count >= 50:
                return "block"

        # 共享链接权限变更
        if "share_link_update" in props:
            if "public_access" in props:
                return "ask"  # 改为公开链接需要确认
            if "password_removed" in props:
                return "ask"  # 移除密码需要确认

        # 批量上传到外部
        if "file_upload" in props and "bulk_send" in props:
            if "external_target" in props:
                return "escalate"

        return None
```

---

## 八、场景拓展对现有文档的影响

### 8.1 需更新的文档

| 文档 | 更新内容 |
|:---|:---|
| [method.md](./method.md) | §12.2 场景列表从 5 个扩展至至少 20+ 个 |
| [detection.py](../../openclaw_guard/engine/detection.py) | 新增群发/导出/批量操作的办公策略规则 |
| [semantic_enhancer.py](../../openclaw_guard/engine/semantic_enhancer.py) | 新增 `channel_broadcast` / `database_query` / `batch_file_upload` 场景识别 |
| [rv-engine-report.md](../architecture/rv-engine-report.md) | BroadcastMonitor / DataExportMonitor / BatchFileMonitor 已落地（6 监视器 + 规约 DSL） |

### 8.2 新增语义标签（13个）

```python
# 需要补充的办公场景标签
BROADCAST_LABELS = ["channel_send", "bulk_send", "cross_org", "external_recipient",
                    "broadcast_message"]
DATA_LABELS = ["database_query", "export_format", "batch_export", "large_export",
               "user_table", "payment_data"]
FILE_BATCH_LABELS = ["file_compress", "file_package", "share_link_update",
                     "public_access", "external_target", "batch_file_upload"]
```

---

## 九、实施建议

### 9.1 分阶段路线

| 阶段 | 场景 | 新增监视器 | 优先级 |
|:---|:---|:---|:---|
| 当前（已接近完成） | 邮件/日报/附件 | MailMonitor, ReportMonitor | P0 |
| **阶段一（本迭代）** | 消息群发、数据库导出、文件批量操作 | BroadcastMonitor, DataExportMonitor, BatchFileMonitor | **P0** |
| 阶段二 | 文档外发、审批代提交、代码推送 | DocShareMonitor, ApproveDelegateMonitor | P1 |
| 阶段三 | 其余高风险场景 | 按需扩展 | P2 |

### 9.2 原有监视器的扩展

`SecurityChainMonitor`（已在开发方案中）可以直接扩展支持上述 P0 场景的链式检测，无需新增太多独立 FSM 类。大部分链式组合检测可以在 `SecurityChainMonitor.feed()` 中通过 `window.sequence_matches()` 实现。

---

## 十、总结

**当前覆盖**：5 个场景（邮件收发、日报生成/外发、附件下载）  
**全量办公场景**：63 个（事前/事中/事后 三阶段）  
**有安全风险需保护**：36 个  
**P0 立即纳入**：3 个（消息群发、数据库导出、文件批量操作）  
**P1 第二阶段**：6 个  
**P2 后续扩展**：剩余 27 个  

**核心结论**：邮件和日报只是个人办公的冰山一角。消息群发、数据库导出、文件批量操作、代提交审批、代码推送等场景的风险更高、更常见，应优先纳入 RV 保护范围。

## 十一、PMKB P0 授权样例与证据

Feishu-derived domains 仅作为个人办公资源分类参考：`IM`、`directory`、
`document/wiki/drive`、`sheets/bitables`、`calendar/meeting`、`workflow/approval`、
`event/network`、`app/config`。每个场景要声明资源 scope（资源 ID/路径、所有者、读写、
数量、数据分类和 recipient zone），并把 principal、agent 和 capability lineage 写入
Authorization Trace。

| P0 policy ID | 场景 trace | 默认 effect | 关键证据 |
|---|---|---|---|
| `EX-10` | `message.send` + `bulk_send` / `broadcast_message` | `openclaw_approval` | recipient、数量、频道范围 |
| `EX-19` | `data.query` / `data.export` | `block` | principal、敏感数据分类、凭据来源 |
| `EX-27` | `file.bulk_transfer` + `external_recipient` | `openclaw_approval` | requested_delta、recipient zone、传输数量 |

四级 fallback 为 `auto_allow_audit`、`clarify_then_retry`、`openclaw_approval`、`block`。
硬阻断优先于任何澄清、白名单或 RV 放宽；未知目标、缺少 principal 或能力链路时不得
自动放行。组合风险（例如 `secret.read + network.egress + external_target`、
`data.export + external_recipient + sensitive_data`、`config.modify + audit.modify`、
`credential.read + process.execute`、`file.write + persistence_location`）保留
`combo_violations` 证据并提升 effect。
