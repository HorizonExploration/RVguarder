# OpenClaw-RVGuarder 语义理解增强方案

> **历史设计提示（2026-09-02 更新）**：本文保留语义层的设计与字段说明，其中出现的 `DetectionEngine`、双轨 HTTP 或“后续迁移”均为历史叙述，不能视为当前实现。当前 PMKB、Authorization Trace、权限组合和 RV 以[权限知识库与 RV 运行时架构结果](../../architecture/permission-kb-runtime-architecture.md)及[v0.7.0-dev 工程统一报告](../../architecture/v070-engineering-unification-report-2026-09-02.md)为准。本文不再作为生产模块清单或调用链路说明。

## 1. 目标与问题

当前项目已经具备稳定的执行前拦截主链，但“输入理解”仍主要停留在关键词、前缀和路径匹配层面，导致以下问题：

- 用户自然语言中的约束条件容易丢失，例如时间范围、作用域、排除条件、数量限制。
- 同义表达、委婉表达、拆句表达和多步复合意图较难被准确识别。
- `conversation.py` 与 `tool_hook_bridge.py` 在“输入归类”阶段已经做了大量启发式判断，错误会一路传递到规则引擎。
- 当前规则引擎适合快速拦截显式高危操作，但不适合处理“意图安全、落地危险”或“表面无害、组合后危险”的情况。

本方案的目标不是替换现有 47 条历史规则，而是在保持快速检测路径可回退的前提下，通过语义增强和 PMKB 权限模型，使 Guard 对输入的理解从“关键词命中”提升为“意图、约束、Authorization Trace 和上下文联合判定”。

## 2. 当前真实链路

结合当前代码，输入理解与风险决策的实际主链如下：

### 2.1 聊天文本入口

`openclaw_guard/conversation.py`

- `infer_event_from_text(text)` 通过正则和关键词把自然语言粗略映射成 `action_type`
- 只做了简单的路径、URL、危险命令提取
- 未显式建模“约束条件”“多步任务”“目标范围”“意图置信度”

### 2.2 OpenClaw Hook 入口

`openclaw_guard/integrations/tool_hook_bridge.py`

- `build_hook_event(payload)` 从工具调用参数中提取 `path/url/command`
- `_infer_action_type(...)` 依赖工具名、参数字符串和关键词推断动作类型
- 这里已经发生了第一次语义压缩，复杂上下文会被折叠成单个 `BehaviorEvent`

### 2.3 行为事件标准化

`openclaw_guard/engine/behavior.py`

- `BehaviorCollectorManager.ingest(payload)` 把 payload 归一化为 `BehaviorEvent`
- 当前 `BehaviorEvent` 只承载动作级字段，没有语义解析结果字段

### 2.4 单事件规则检测（已重构）

`openclaw_guard/engine/detection.py`

- `DetectionEngine.evaluate(event)` 已切换为语义优先模式
- 优先消费 `event.metadata["semantic"]` 中的结构化标签和 `scenario` 做决策
- 办公场景策略（邮件外发、日报外发等）优先于通用规则匹配执行
- 47 条规则保留为规则集合，但匹配输入已从原始字符串/前缀切换为语义标签
- 若事件缺少语义元数据，`_ensure_semantic_payload()` 会自动补齐

### 2.5 审批与执行控制

`openclaw_guard/engine/control.py`

- `GuardController.decide(...)` 在规则结果上叠加白名单和审批状态
- 这里负责把 `DetectionDecision` 变成 `ControlledAction`

### 2.6 当前运行时主入口

`openclaw_guard/manager.py`

- `ingest_event(...)` 是聊天侧的主入口
- `handle_before_tool_call(...)` 是 Hook 侧的主入口
- 两处都会执行：`event -> semantic/Trace -> detector.evaluate(event) -> AuthorizationPolicyEngine -> ConstraintEngine -> RV -> controller.decide(...)`

## 3. 当前局限的根因

当前“只停留在关键词匹配”，不只是 `DetectionEngine` 的问题，而是整条链路都以启发式归类为主：

1. 输入在进入检测前，已经被压缩成单个 `action_type`
2. `BehaviorEvent` 没有保存“原始意图解析结果”
3. `DetectionEngine` 只看单个事件，不看跨步骤 Trace
4. 当前没有“约束保真”机制，无法验证自然语言到执行计划是否失真
5. 当前没有稳定的用户自定义规则入口，只有固定内置规则和白名单

另外还有一个架构层面的现状需要明确：

- 当前真正生效的主链在 `manager.py`
- `openclaw_guard/core/action_service.py` 中存在 `detector.decide / whitelist.refine / controller.enforce` 这类与现状不一致的接口调用痕迹，说明服务层和主链尚未完全统一

因此，语义增强功能应优先接入 `manager.py` 当前主链，后续再统一收敛到 service 层，避免出现“双入口、双决策链”。

## 4. 总体设计原则

- 规则优先：高确定性的显式高危规则继续保持最快路径
- 语义补充：只在规则未命中、信息不完整或高风险场景下触发 LLM
- 结构化输出：LLM 不直接给最终裁决，而是输出可审计的结构化语义结果
- 可验证：任何语义解析结果都必须进入 Trace、审计和可回放链路
- 可回退：LLM 不可用时必须退回现有规则 + fallback 逻辑
- 分阶段落地：先做单事件语义增强，再做多事件 Trace/RV，最后做规则自学习

## 5. 新链路（已部分实现）

当前已实现链路：

```text
原始输入 / Hook payload
        │
        ├─ BehaviorCollectorManager.ingest()
        │    └─ 归一化为 BehaviorEvent
        │
        ├─ OpenclawGuardManager._annotate_event_context()
        │    ├─ 标注 workspace 边界
        │    ├─ 调用 SemanticEnhancer.evaluate()
        │    ├─ 写入 event.metadata["semantic"]
        │    └─ 写入 event.metadata["rv_trace"]
        │
        ├─ DetectionEngine.evaluate()
        │    ├─ 确保语义载荷存在（兜底补齐）
        │    ├─ 办公场景策略优先判定
        │    ├─ 语义标签规则匹配
        │    └─ fallback 决策
        │
        ├─ AuthorizationPolicyEngine（PMKB 1.1.0）
        │    ├─ TraceCompiler / 覆盖状态
        │    ├─ 单步规则与风险评分
        │    ├─ PermissionClosure / PermissionDiff
        │    └─ RiskGraph 危险权限组合
        │
        ├─ ConstraintEngine（可选升权）
        │
        ├─ RuntimeVerificationEngine + PrincipalSecurityState
        │    └─ session / principal 跨步骤组合风险与不变量检测

        ├─ GuardController.decide(...)
        │    └─ 叠加白名单与审批状态
        │
        └─ ControlledAction 保存 + 审计写入
```

仍属后续增强（当前不作为自动放行依据）：

```text
        ├─ BackTranslationVerifier.verify()
        │    └─ 检查 trace 是否丢失原始约束
        │
        └─ BackTranslationVerifier / 更强的 DecisionFusion 校验
```

## 6. 关键模块设计

### 6.1 EventNormalizer

目的：在 `BehaviorEvent` 落库前，保留更多语义上下文，而不是只保留压缩后的动作字段。

建议新增的标准化结果：

```json
{
  "raw_user_intent": "清理 tmp 下 7 天前的缓存，但不要删除日志",
  "candidate_actions": ["file_delete"],
  "constraints": {
    "time_range": "older_than_7_days",
    "scope": ["/tmp"],
    "exclude": ["*.log", "logs"]
  },
  "parse_confidence": 0.62,
  "normalization_source": "conversation|hook"
}
```

建议落点：

- 聊天侧：扩展 `conversation.py::infer_event_from_text`
- Hook 侧：扩展 `tool_hook_bridge.py::build_hook_event`
- 存储侧：先放到 `BehaviorEvent.metadata`，避免第一阶段就大改 dataclass

这样做的原因是当前 `BehaviorEvent` 模型很稳定，第一阶段不宜一次性侵入所有序列化代码。

### 6.2 SemanticEnhancer（已实现）

职责：作为独立语义层模块，对每个进入主链的事件产出结构化语义结果与 `rv_trace`，由
`TraceCompiler` 编译为 PMKB 与 RV 共同消费的 Authorization Trace，再供 `DetectionEngine`
和后续 RV 层使用。

已实现模块：

- `openclaw_guard/engine/semantic_enhancer.py`

当前支持两种模式：

1. **LLM 模式**（默认优先）：若配置了 `DEEPSEEK_API_KEY` 环境变量或通过构造函数传入 `api_key`，优先调用 DeepSeek Chat API
   - Prompt 设计包含完整的 schema 说明和可选标签列表
   - 要求 LLM 以 `response_format: json_object` 输出严格 JSON
   - 解析失败/超时/返回非 JSON 时自动降级到本地规则化实现
   - 超时阈值：10 秒
2. **本地规则化模式**（降级回退）：不使用 LLM 或 LLM 不可用时自动回退
   - 覆盖 7 个维度的标签提取
   - 延迟 < 1ms

调用优先级：LLM API > 本地规则化降级

已实现接口：

```python
class SemanticEnhancer:
    def evaluate(self, event: BehaviorEvent, context: dict[str, Any]) -> dict[str, Any]:
        ...
```

返回值结构（当前 v2 版本）：

```python
{
    "semantic": {
        "version": "v2",
        "engine": "builtin-semantic-enhancer",
        "origin": "chat" | "hook" | "reply",
        "scenario": "mail_send" | "report_send" | ... | event.action_type,
        "intent": {"category": str, "goal": str},
        "entities": {"paths": [...], "urls": [...], "recipients": [...], "tool_name": str | None},
        "constraints": {"has_exclude": bool, "has_time_constraint": bool, ...},
        "confidence": float,
        "labels": ["command_rm_rf", "path_system_root", "external_recipient", ...],
    },
    "rv_trace": [
        {
            "step_id": "s1",
            "event": "mail_send",
            "props": ["mail_send", "external_recipient", "contains_secret", ...],
        }
    ],
}
```

标签分类（共 7 个维度）：

- 基础标签：`action_type`、`scenario`、`outside_workspace`、`multi_target`、`unparsed_target`、`command_readonly`
- 命令标签：`command_rm_rf`、`command_sudo`、`command_pipe_curl_sh` 等
- 路径标签：`path_system_root`、`path_sensitive_creds`、`path_log`、`path_high_value` 等
- 网络标签：`network_http`、`network_webhook`、`network_secret_payload`、`network_public_ip` 等
- 配置标签：`config_auth_disable`、`config_audit_disable`、`config_bypass` 等
- 渠道/技能标签：`channel_external_send`、`skill_persistence`、`skill_system_admin` 等
- 办公场景标签：`has_recipient`、`external_recipient`、`contains_attachment`、`contains_secret`、`ai_generated_content`、`internal_source`、`missing_scope_constraint` 等

当前版本为 LLM-first 实现：默认调用 DeepSeek `deepseek-v4-flash` 模型进行语义理解，解析失败/超时/返回非 JSON 时自动回退到本地规则化降级实现。

### 6.3 LLM 结构化输出

推荐使用响应速度快的小模型 API，DeepSeek 可作为优先候选，但应通过统一抽象封装，不把模型厂商写死在主链中。

建议输出 schema：

```json
{
  "intent": {
    "category": "cleanup",
    "goal": "delete cache files",
    "risk_focus": "possible over-deletion"
  },
  "entities": {
    "paths": ["/tmp"],
    "patterns": [".cache"],
    "urls": [],
    "commands": []
  },
  "constraints": {
    "time_range": "older_than_7_days",
    "exclude": ["logs", "*.log"],
    "must_confirm": false
  },
  "trace": [
    {
      "step_id": "s1",
      "action_type": "file_search",
      "target": "/tmp",
      "condition": "name=.cache and mtime>7d"
    },
    {
      "step_id": "s2",
      "action_type": "file_delete",
      "target": "results_of_s1"
    }
  ],
  "risk": {
    "level": "dangerous",
    "score": 0.78,
    "reason": "delete scope may exceed cache only"
  },
  "alignment": {
    "intent_command_consistent": true,
    "missing_constraints": []
  },
  "confidence": 0.84
}
```

要求：

- 必须是严格 JSON
- 字段缺失时返回空数组或空对象，不返回自然语言段落
- 必须给出 `confidence`
- 必须输出 `trace`
- 必须列出 `missing_constraints`

### 6.4 DecisionFusion（当前已实现的核心逻辑）

当前实现的中决策融合策略（位于 `detection.py`）：

1. 办公场景策略优先（`_office_decision()`）：
   - `mail_send + external_recipient + contains_secret -> block`
   - `report_send + external_recipient + internal_source -> block`
   - `mail_send + bulk_send -> escalate`
   - `mail_send + ai_generated_content + 无人审阅 -> ask`
   - `report_generate + missing_scope_constraint -> ask`
2. 语义标签规则匹配：
   - 历史 47 条规则仍保留，但匹配输入为语义标签集合而非原始字符串
   - PMKB 1.1.0 随后以 Authorization Trace 评估单步权限、最小权限差分和危险组合
   - 命中规则后取最强风险等级对应的决策
3. fallback 决策（`_fallback_decision()`）：
   - 邮件/日报外发场景默认 `ask`
   - 命令/文件/网络/配置等敏感动作默认 `ask`
   - 只读命令和聊天消息按低风险 `allow`

LLM 不直接替代规则引擎，也不直接做最终授权，而是作为语义标签的增强来源参与融合。未配置
LLM 时本地规则化实现仍可输出 Trace；`unknown/partial/conflict` 进入澄清或 OpenClaw 审批，
不会因分数相似而自动放行。

### 6.5 Back-translation

这是本方案非常重要的一层，因为它能解决“自然语言约束丢失”的问题。

核心思想：

1. LLM 把用户输入解析成 Trace
2. 再把 Trace 反向重写为自然语言
3. 对比原始输入与重建输入是否一致
4. 如果发现关键约束丢失，则把该请求升级为 `ask` 或重新请求解析

示例：

- 原始输入：`清理 tmp 下 7 天前的缓存，不要删日志`
- 语义 Trace：`find /tmp -name .cache -mtime +7 -> delete`
- 回译结果：`删除 /tmp 中 7 天前的 .cache 文件`

如果回译中缺失了“不删日志”，则说明 Trace 不能安全代表原意，应：

- 触发一次精炼解析，或
- 直接要求人工确认

建议触发场景：

- `file_delete`
- `config_modify`
- `network_egress`
- 多步 `command_exec`

第一阶段不必做复杂文本相似度模型，可先基于：

- 约束词覆盖率
- 关键实体覆盖率
- 风险实体是否新增

## 7. Trace 风险检测

当前 `DetectionEngine` 是单事件判定，只适合 3A。

### 7.1 3A 单条指令规则检测

保留现有：

- `DetectionEngine.evaluate(event)`
- 47 条规则继续作为第一道门

### 7.2 3B 链式风险检测

已实现：

- `RuntimeVerificationEngine`（`rv/runtime_verification.py`）

建议新增：

- `TraceRiskAnalyzer`

职责：

- 识别“先搜索、后删除”“先导出、后外传”“先改配置、后关闭审计”这类组合风险
- 在最近 N 个动作窗口内做滑动检查
- 用轻量 DSL 定义不变量

示例不变量：

```text
G( config_modify(audit=off) -> X ask_or_block )
G( file_search(sensitive=true) -> F<=3 network_egress => escalate )
G( file_delete(target in high_value_path) -> ask )
```

第一阶段不必实现完整 LTL，可先实现固定窗口规则：

- 最近 5 个动作
- 最近 3 分钟
- 按 `action_type + target_summary + metadata` 做简单模式匹配

这样更贴合当前项目体量。

### 7.3 3C 意图-命令对齐检测

这里建议高风险时触发，而不是全量触发。

目的：

- 用户说“查看一下”
- 实际工具准备执行“删除、覆盖、上传”

这种场景仅靠关键词容易漏掉，需要比较：

- 原始意图
- 语义 Trace
- 真正工具参数 / 命令 / 目标路径

建议对齐结果：

```json
{
  "aligned": false,
  "severity": "high",
  "reason": "intent is readonly, but command mutates filesystem",
  "evidence": {
    "intent": "查看日志",
    "actual_command": "rm -rf /var/log/app"
  }
}
```

若未对齐，至少 `ask`，严重时直接 `block`。

### 7.4 3D 解域验证

`SolutionDomainValidator` 的目标是确认“执行解”是否还在用户允许的问题域内。

重点验证：

- 路径是否越界
- URL 是否越界
- 是否从只读任务漂移成写操作
- 是否突破用户明确给出的约束条件

这层更适合放在 Hook 侧，因为此时拿到的是真实工具参数。

### 7.5 验证引擎选型

语义理解要真正服务于后续 RV，不应该只输出“风险分数”，而应该输出能被验证引擎消费的结构化 Trace。对当前项目而言，验证引擎的选择标准应为：

- 能做在线监视，而不是只适合离线证明
- 能与 Python 主链直接集成
- 能处理有限窗口内的连续工具调用
- 能表达“先 A 后 B”“A 之后禁止 B”“必须带约束 C”这类安全属性
- 部署成本可控，不显著增加 Guard 的启动和运维复杂度

基于当前项目形态，建议采用“在线主引擎自研、离线增强可选”的策略，而不是直接把现成学术 RV 工具塞进主链。

#### 第一层：内置轻量 Runtime Monitor

建议作为主运行引擎，直接集成到 `openclaw_guard/rv/runtime_verification.py`。

实现方式：

- 由语义层直接产出 `rv_trace`，RV 层直接消费
- 每个事件携带原子命题标签，例如：
  - `file_delete`
  - `outside_workspace`
  - `high_value_path`
  - `contains_secret`
  - `network_public`
  - `audit_disabled`
- 使用有限状态机或窗口监视器持续更新状态
- 一旦违反不变量，立即返回 `ask / block / escalate`

适合当前项目的原因：

- 与 Python 现有代码最容易集成
- 可直接挂在 `manager.handle_before_tool_call()` 与 `handle_after_tool_call()` 上
- 时延低，适合在线审批
- 容易把用户规则编译成监视器规则

建议第一阶段支持的属性类型：

- 顺序约束：先搜索后删除、先导出后外传
- 禁止组合：关闭审计后继续配置修改
- 范围约束：高价值路径删除必须审批
- 约束保真：若 Trace 丢失时间/范围/排除条件，则直接升级

#### 第二层：可选离线形式化引擎

建议作为研究与增强层，不直接放在实时链路中心。

候选优先级：

1. `Spot`
   - 优点：LTL/automata 生态成熟，适合把公式编译为自动机
   - 用途：离线验证规则正确性、验证 DSL 公式、将部分属性预编译为监视器
   - 缺点：依赖和部署较重，不适合先作为在线主引擎；许可证与主项目分发策略也需要额外审慎评估
2. 自定义 LTLf/有限轨迹编译器
   - 优点：最贴合本项目，只支持需要的有限时序子集即可
   - 用途：将用户 DSL 编译到内置监视器
   - 缺点：需要自行维护语义与测试
3. `MonPoly` / `RV-Monitor` 类工具
   - 优点：学术上成熟
   - 缺点：与当前 Python 本地插件形态集成成本高，运行链复杂，不适合作为第一选择

补充判断：

- 当前不存在一个既能开箱即用、又同时满足 `Python 主链`、`插件即用`、`办公场景适配`、`在线低时延` 和 `初学者可维护` 的现成 RV 引擎
- 因此，现成 RV 工具最多作为“可借力组件”或“离线增强组件”，不作为当前主链默认依赖

当前项目的推荐结论：

- 在线主引擎：自研轻量 `RuntimeVerificationEngine`
- 离线增强引擎：后续可选接入 `Spot` 做公式校验、自动机生成和研究验证
- 当前不作为默认主链依赖：`MonPoly`、`RV-Monitor`、其他重型多语言生态 RV 框架

不建议当前直接把 `Spot`、`MonPoly` 或 Java/OCaml 生态的 RV 引擎硬接入主链，否则会显著增加部署复杂度，并削弱“插件开启即用”的目标。

### 7.6 语义层与 RV 的接口要求

当前实现已在语义层和策略/RV 层之间使用 `TraceCompiler` 作为稳定适配边界。`SemanticEnhancer`
保留语义实体、标签和置信度，`TraceCompiler` 将其编译为 PMKB 与 RV 共同消费的
Authorization Trace；这样既避免下游重复解析，也能集中记录 coverage gap 和 provenance。

为了让后续验证引擎可用，`SemanticEnhancer` 的输出必须满足以下要求：

- 必须产生可执行前的 `trace`
- 必须显式保留约束条件，而不是只保留自然语言摘要
- 必须把高风险实体转成结构化标签
- 必须给出“是否缺失约束”的布尔或枚举结果
- 必须直接产出标准化 `rv_trace`

推荐的直接接口形式如下：

```json
{
  "semantic": {
    "intent": {},
    "entities": {},
    "constraints": {},
    "confidence": 0.0
  },
  "rv_trace": [
    {
      "step_id": "s1",
      "event": "file_search",
      "props": ["path_tmp", "pattern_cache", "older_than_7_days"]
    },
    {
      "step_id": "s2",
      "event": "file_delete",
      "props": ["derived_from_s1", "mutable", "requires_scope_guard"]
    }
  ]
}
```

说明：

- `semantic` 用于保留语义理解结果和审计证据
- `AuthorizationTrace` 是 PMKB 与 RV 之间稳定依赖的结构化对象；`rv_trace` 仍作为历史兼容字段透传
- 当前 `TraceCompiler` 已承担转换和覆盖计算，不再要求每个下游自行解释原始标签
- 如果未来出现更多策略引擎，再扩展 Trace schema，而不是新增平行解析链

这样语义层和 RV 层之间就不是松散文本接口，而是简洁但稳定的验证接口。

## 8. 用户自定义规则

这部分建议分两类实现，不要一开始就上完整 DSL。

### 8.1 第一类：结构化用户规则

适合配置到 `policies/`：

```json
{
  "rule_id": "USR-001",
  "when": {
    "action_type": "file_delete",
    "path_prefixes": ["/cases", "/evidence"]
  },
  "then": {
    "action": "block",
    "reason": "案件证据目录不允许直接删除"
  }
}
```

这类规则可以直接复用现有 `DetectionRule` 思路，成本最低。

### 8.2 第二类：自然语言规则

例如：

- “不要让 OpenClaw 删除家目录下的任何 SSH 配置”
- “凡是外传带 token 的内容都必须拦截”

不建议直接执行自然语言规则，而是走：

自然语言规则 -> LLM 结构化提取 -> 生成显式规则 -> 用户确认 -> 落到 `policies/`

这样才能保持可审计、可回放、可解释。

## 9. 与当前代码的落地映射

### 第一阶段：已完成

当前已实现的模块与能力：

1. `openclaw_guard/engine/semantic_enhancer.py`
   - 独立语义层模块，已实现 `SemanticEnhancer` 类
   - 支持 LLM API 模式（DeepSeek Chat）与本地规则化降级回退两种方式
   - API key 通过环境变量 `DEEPSEEK_API_KEY` 或构造函数注入
   - 默认模型为 `deepseek-v4-flash`
   - LLM 调用失败/超时/返回非 JSON 时自动降级到本地规则化实现
   - 覆盖 7 个维度标签：基础、命令、路径、网络、配置、渠道/技能、办公场景
   - 识别 5 种办公场景：`mail_send`、`mail_read`、`report_send`、`report_generate`、`attachment_download`
   - 直接产出 `semantic` + `rv_trace`

2. `openclaw_guard/engine/detection.py`
   - `DetectionEngine.evaluate()` 已改为语义优先模式
   - 优先执行办公场景策略（`_office_decision()`）
   - 再执行语义标签规则匹配（`_semantic_predicates()`）
   - 最后走 fallback 决策
   - 内置 `SemanticEnhancer` 实例，兜底补齐缺失的语义元数据

3. `openclaw_guard/manager.py`
   - `_annotate_event_context()` 统一负责所有入口的语义标注
   - 聊天入口 `ingest_event()` 已接入语义增强
   - Hook 入口 `handle_before_tool_call()` 已接入语义增强
   - 回复回读 `reply_scan` 已补齐语义标注
   - 语义结果写入 `event.metadata["semantic"]` 和 `event.metadata["rv_trace"]`

4. `openclaw_guard/engine/__init__.py`
   - `SemanticEnhancer` 已加入统一导出

5. `pyproject.toml`
   - 打包配置已改为自动发现子包

### 第二阶段：Trace 与 RV

建议新增：

- `openclaw_guard/rv/runtime_verification.py`
- `openclaw_guard/engine/trace_analyzer.py`

并在 `manager.handle_before_tool_call()` 和 `handle_after_tool_call()` 中维护最近动作窗口。

### 第三阶段：用户规则和 RV 反馈

建议新增：

- `RuleExtractionService`
- `RuleFeedbackService`

当 RV 命中违规窗口时：

1. 抽取窗口中的共性模式
2. 生成人工可读的候选规则
3. 由用户确认后写入 `policies/`

这里不要自动写规则，必须有人审阅。

## 10. 性能与降级策略

当前版本语义层支持两种模式：

- **本地模式**（默认无 API key 时）：延迟 < 1ms
- **LLM 模式**（配置 API key 后）：平均延迟 200ms - 500ms（取决于 DeepSeek API 响应速度）

后续预算建议：

- 规则命中：`< 10ms`
- 语义增强（本地）：`< 1ms`
- 语义增强（LLM）：`200ms - 500ms`
- Back-translation：只在高风险场景触发
- RV：本地窗口分析，尽量不调用 LLM

必须具备的降级路径：

- LLM 超时 -> 回退到现有本地语义标签 + fallback
- LLM 返回非 JSON -> 记审计并回退
- LLM 置信度低 -> 仅作为辅助证据，不直接放行
- Hook 实时链路中若预算不足 -> 优先保守 `ask`

## 11. 当前使用的数据结构

语义结果通过 `event.metadata` 挂载，不直接改动 `BehaviorEvent` dataclass。

当前 v2 版本实际结构：

```json
{
  "semantic": {
    "version": "v2",
    "engine": "builtin-semantic-enhancer",
    "origin": "chat|hook|reply",
    "scenario": "mail_send",
    "intent": {
      "category": "mail_send",
      "goal": "send email to external recipient"
    },
    "entities": {
      "paths": [],
      "urls": [],
      "recipients": ["alice@example.com"],
      "tool_name": null
    },
    "constraints": {
      "has_exclude": true,
      "has_time_constraint": false,
      "has_scope_constraint": false,
      "requires_human_review": false
    },
    "confidence": 0.65,
    "labels": [
      "mail_send", "external_recipient", "contains_secret", "network_egress"
    ]
  },
  "rv_trace": [
    {
      "step_id": "s1",
      "event": "mail_send",
      "props": [
        "mail_send", "external_recipient", "contains_secret"
      ]
    }
  ]
}
```

说明：

- `semantic`：保留完整语义理解结果，用于审计、调参与前端展示
- `rv_trace`：从语义标签中直接派生，是 RV 层的稳定输入
- 等主链稳定后，可考虑把 `semantic` 抽成专门 dataclass

## 12. 面向 OpenClaw 安全插件定位的重新评估

### 12.1 核心定位重述

项目的最终定位不应是一个“泛用安全实验器”，而应是：

- 面向 OpenClaw 的本地安全插件
- 围绕高频办公与个人生产力场景提供执行前保护
- 在不破坏 OpenClaw 原有工作流的前提下提供审计、审批、约束保真和运行时验证
- 能被初学者逐步维护，而不是只能靠一次性堆砌复杂技术完成

因此，后续方案必须优先满足四个要求：

- 对真实高频场景有清晰覆盖，而不是只覆盖抽象动作类型
- 运行时链路低时延、可解释、可降级
- 架构尽量收敛，减少双入口、双实现、双规则源
- 开发栈对初学者友好，能边做边学、边学边交付

### 12.2 围绕高频办公场景的目标收敛

参考 OpenClaw 的常见落地方式，当前项目最值得优先覆盖的核心场景应收敛为：

1. 邮件收发与邮件处理
   - 读取收件箱、识别重要邮件
   - 基于上下文起草回复
   - 发送、转发、归档、加标签
2. 日报/晨报/周报摘要
   - 拉取邮件、日历、RSS、任务列表、代码托管更新
   - 生成摘要并通过邮件或 IM 渠道外发
3. 个人知识整理与对外发送
   - 汇总文档、链接、附件
   - 输出总结、附件包、分享邮件
4. 办公自动化中的批量操作
   - 批量归档邮件
   - 批量下载附件
   - 批量发送日报或通知

这些场景的共同特征是：

- 高度依赖语义理解和上下文
- 同时涉及高风险外发、敏感信息处理和多步骤自动化
- 需要“生成 + 判断 + 执行 + 审计”的完整闭环

### 12.3 从三个维度重评当前方案

#### A. 初学者可落地性

现有短板：

- 概念层很多，但实现主链还没有完全统一，`manager.py` 与 `ActionService` 存在不一致痕迹
- 直接讨论 LTL、RV、Back-translation、用户 DSL，容易超出初学者第一阶段可掌控范围
- 当前规则、语义、审批、Hook、审计已经较多，若再同时引入复杂外部引擎，学习负担会过高

优化方向：

- 第一阶段只保留“规则 + 结构化语义 + 轻量运行时监视器”
- 先用 `metadata` 承载语义结果，不立刻重构全部模型
- 先做固定模板规则和有限窗口验证，不急于完整 DSL
- 先做 2 个核心场景：邮件发送、日报生成与外发

#### B. 场景安全覆盖能力

现有短板：

- 当前动作类型只覆盖 `file / config / network / channel / skill / command` 的抽象层
- 对“邮件草拟但未发送”和“邮件已实际发送”的安全差异没有单独建模
- 对“日报生成”“日报外发”“多源摘要汇总”等典型办公流程缺少场景级风险规则
- 还没有对附件、收件人域名、群发、抄送、敏感词、外部域外发做针对性约束

优化方向：

- 在抽象动作之上增加场景语义标签：
  - `mail_read`
  - `mail_draft`
  - `mail_send`
  - `report_generate`
  - `report_send`
  - `attachment_download`
- 为邮件和日报场景建立专门的高风险原子命题：
  - `external_recipient`
  - `bulk_send`
  - `contains_attachment`
  - `contains_secret`
  - `cross_domain_share`
  - `auto_generated_report`

#### C. 长期维护成本

现有短板：

- 规则体系目前偏单层，场景扩展后容易膨胀
- 若直接接入重型验证引擎，部署和排障成本会显著上升
- 若让 LLM 直接决定放行/阻断，后续调参与审计成本很高

优化方向：

- 维持“规则层、语义层、验证层、审批层”分层边界
- LLM 只输出结构化结果，不直接输出最终执行裁决
- 在线主链使用轻量监视器，复杂形式化工具作为离线增强层
- 明确默认支持的核心场景，避免一开始覆盖过多办公自动化能力

## 13. 场景化安全模型

### 13.1 邮件收发场景

邮件场景下，安全插件的重点不是“会不会发邮件”，而是“是否在正确的对象、正确的范围、正确的上下文下发邮件”。

需要重点保护的风险：

- 向外部域名发送内部信息
- 错发收件人、群发、抄送过多联系人
- 自动回复中包含合同、凭据、价格、身份证号、客户资料等敏感信息
- 将 AI 生成内容未经确认直接外发
- 将附件自动转发给非白名单域名

建议的场景规则：

- `mail_send + external_recipient + contains_secret -> block`
- `mail_send + bulk_send -> escalate`
- `mail_send + ai_generated_content + no_human_review -> ask`
- `attachment_download -> mail_send -> external_recipient -> escalate`

### 13.2 日报/简报场景

日报流程看似低风险，实际包含多源聚合和外发行为，必须重点关注：

- 摘要来源是否越权
- 摘要是否混入敏感信息
- 日报接收对象是否符合权限边界
- 是否存在把内部系统状态、未公开缺陷、未脱敏数据自动外发的情况

建议的场景规则：

- `report_generate + source_contains_internal_ticket -> ask`
- `report_send + external_recipient + internal_source -> block`
- `report_generate + missing_scope_constraint -> ask`
- `calendar + mail + github + summary -> requires_provenance_check`

### 13.3 面向办公场景的最小安全闭环

对于邮件和日报这两类高频场景，最小闭环应为：

1. 识别场景语义
2. 提取约束和目标对象
3. 生成 `trace`
4. 对 `trace` 做 RV 检查
5. 对外发类动作执行人工确认或策略审批
6. 写入完整审计

只有做到这六步，项目才真正符合“OpenClaw 安全插件”的核心定位。

## 14. 引擎与技术栈重新选型

### 14.1 选型原则

重新选型时，应同时满足：

- 匹配当前 Python 主链和 OpenClaw Hook 接入方式
- 支持后续邮件、日报、多源摘要等办公场景扩展
- 对初学者学习曲线友好
- 维护复杂度和部署成本可控
- 默认优先本地可解释能力，而不是优先外部重型平台

### 14.2 推荐引擎组合

#### 语义理解引擎

推荐方案：

- 规则引擎：保留现有 `DetectionEngine`
- 语义增强：轻量 LLM API + 严格结构化输出
- 数据校验：`Pydantic` 风格 schema 校验

原因：

- 对初学者而言，“规则 + schema + 结构化调用”比直接做自由文本 agent 更容易调试
- 对后续 RV 而言，结构化输出远比自然语言结果更稳定

不建议：

- 让 LLM 直接输出最终放行/阻断结果
- 引入过度复杂的 prompt orchestration 框架

#### 运行时验证引擎

推荐方案：

- 在线主引擎：自研轻量 `RuntimeVerificationEngine`
- 表达形式：有限状态机 + 有限窗口规则 + 轻量 DSL
- 离线增强：后续可选 `Spot`

原因：

- 最符合当前项目“低时延 + 插件即用 + 容易本地调试”的要求
- 对初学者而言，可先从“规则模板 -> 状态机”理解，再逐步过渡到时序逻辑

#### 工作流/调度引擎

推荐方案：

- 第一阶段：`APScheduler`
- 第二阶段：仍不建议上 `Temporal` / `Airflow` / `Prefect`

原因：

- 邮件轮询、日报定时生成、外发提醒，本质都是轻量定时任务
- `APScheduler` 足够覆盖当前需求，且学习成本明显更低

#### HTTP 与集成层

推荐方案：

- HTTP 客户端：`httpx`
- 外部服务适配：继续保留现有 adapter 方式，每类集成一个独立模块

原因：

- 与 async/timeout/retry 语义兼容性更好
- 比起继续堆在单个 manager 中，更适合长期维护

#### 邮件与办公连接器

推荐方案：

- 邮件：先支持 `IMAP/SMTP`
- 企业邮箱：后续扩展 Gmail API / Microsoft Graph
- 日报数据源：先支持邮件、日历、RSS、GitHub，再逐步扩展 IM/任务系统

原因：

- `IMAP/SMTP` 最通用，便于先完成场景验证
- 企业生态 API 可以在核心能力稳定后再接入

#### 持久化与审计

推荐方案：

- 默认继续使用 `SQLite + JSONL`
- 保留 PostgreSQL 为可选扩展

原因：

- 对初学者和本地插件场景最友好
- 不增加部署门槛

#### 自动化测试

推荐方案：

- 单元测试：保留 `unittest`
- 场景测试：新增少量 workflow fixture
- 不建议第一阶段引入过重的测试平台

原因：

- 当前项目已经使用 `unittest`
- 初学者继续沿用现有测试基础更稳妥

### 14.3 技术栈最终建议

推荐的长期可维护组合：

- 语言：Python
- Web/API：现有 HTTP 服务结构，后续逐步模块化
- 语义层：轻量 LLM API + `Pydantic` schema
- 规则层：现有 `DetectionEngine` 演进
- RV 层：自研 `RuntimeVerificationEngine`
- 调度层：`APScheduler`
- 集成层：`httpx` + adapter 模式
- 存储层：SQLite + JSONL，PostgreSQL 可选
- 前端：保持当前独立前端工程，不把复杂业务逻辑塞进前端

这套组合比“重型工作流平台 + 重型形式化工具 + 多语言混合栈”更适合本项目的长期维护和初学者成长节奏。

## 15. 推荐实施顺序

### P1 语义补全

- 保留当前规则引擎
- 新增 `SemanticEnhancer`
- 在 `manager.py` 主链接入
- 对 `file_delete / file_write / config_modify / network_egress / mail_send / report_send` 先覆盖

### P2 办公场景建模

- 为邮件和日报场景补充专用语义标签
- 新增外发对象、群发、附件、敏感信息等原子命题
- 让 `trace` 与 `rv_trace` 可直接表达办公场景约束

### P3 约束保真

- 新增 `BackTranslationVerifier`
- 检查时间、范围、排除条件是否丢失
- 对外发类动作启用更严格的一致性校验

### P4 多步风险

- 新增 Trace 窗口和 RV 检查
- 先做固定模板规则，不急着上完整 DSL
- 把邮件、日报、附件流转纳入多步风险检测

### P5 用户规则

- 支持结构化自定义规则
- 支持自然语言规则提取为显式规则

### P6 反馈闭环

- 从 RV 违规窗口中生成候选规则
- 人工确认后补全规则库

## 16. 对初学者的实现建议

为了兼顾学习与交付，建议按“能跑、能看懂、能测试、能迭代”的顺序开发：

1. 先读懂当前主链：`conversation.py -> manager.py -> detection.py -> control.py`
2. 先实现结构化输出和日志，而不是一开始追求复杂形式化能力
3. 先把邮件发送和日报外发两类动作做严，再扩展其他办公场景
4. 每新增一个场景，都要同步补：
   - 一个最小规则
   - 一个最小语义样例
   - 一个最小 RV 检查
   - 一个最小审计样例

这样更适合在学习过程中稳定积累，而不是被过大的抽象层压垮。

## 17. 结论

结合当前项目实际情况，最合理的方案不是“把 LLM 塞进 `DetectionEngine` 替代规则”，也不是“先接入重型形式化引擎再补场景”，而是：

1. 把项目明确收敛为 OpenClaw 的办公安全插件
2. 优先覆盖邮件收发、日报生成与外发等高频核心场景
3. 保留现有规则引擎作为快速硬规则层
4. 在 `manager.py` 的真实主链里增加语义增强编排
5. 用结构化 LLM 输出生成 `trace`、`rv_trace` 和约束信息
6. 用轻量 `RuntimeVerificationEngine` 做在线监视
7. 用 `Spot` 这类工具作为后续离线增强层，而不是实时主链依赖
8. 用分阶段、初学者友好的方式持续演进

这样可以最大程度复用当前项目已经稳定的拦截、审批、审计和 Hook 链路，同时把“只靠关键词匹配”的短板逐步替换为“规则 + 语义 + Trace + RV + 场景化约束”的组合防线。

## 18. PMKB 授权策略合同（Task 9）

PMKB（Permission Model Knowledge Base）借鉴 Feishu 的权限分层经验，但只描述
OpenClaw 本地运行时可验证的能力，不复制租户级 scope。Feishu-derived domains 映射为
`IM`、`directory`、`document/wiki/drive`、`sheets/bitables`、`calendar/meeting`、
`workflow/approval`、`event/network` 和 `app/config`；个人办公资源 scope 还必须明确
资源 ID/路径、所有者、读写动作、数量、数据分类和收件人区域。

### 18.1 Authorization Trace 与 policy_decision

每次 Hook 决策都保留一个只读的 Authorization Trace，区分 `principal`、`agent_id`、
`session_id`、`capability_lineage`、工具/operation、资源 scope、data classification、
目的、来源和字段置信度。策略层只产生证据，不替代 OpenClaw 执行审批。序列化的
`policy_decision` 形状如下（字段可为空但不可删除）：

```json
{
  "effect": "auto_allow_audit",
  "match_status": "matched",
  "missing_features": [],
  "requested_delta": [
    {"family": "data.export", "resource_type": "table", "resource_ids": ["tbl-1"], "scope": "own", "classification": "internal", "field_scope": [], "purpose": "report", "ttl_seconds": 300}
  ],
  "redundant_permissions": [],
  "excessive_permissions": [],
  "scope_expansions": [],
  "hard_violations": [],
  "effective_permissions": [],
  "p_after": [],
  "combo_violations": [],
  "policy_version": "1.1.0"
}
```

`requested_delta`、`redundant_permissions`、`excessive_permissions`、`effective_permissions`
和 `p_after` 序列化为完整 `PermissionRef` 对象（操作、资源类型/ID、scope、分类、字段
范围、purpose 和 TTL），而不是展示字符串。
评估耗时不属于 `policy_decision`：当前实现以 `policy_ms` 保存在事件
metadata/pipeline timings 中；`evaluation_ms` 与聚合 `p95_ms` 等兼容指标待后续
只读采集器实现后再启用。

P0 规则示例来自版本化 bundle：`EX-10`（`message.send` 消息群发/广播）、
`EX-19`（`data.query`/`data.export` 数据库查询与导出中的敏感读取）和
`EX-27`（`file.bulk_transfer` 文件批量传输）。P0 trace 必须保留对应 rule ID，
并记录命中规则、缺失字段及组合风险，便于回放而不暴露数据内容。

### 18.2 四级路由与优先级

正常路由为 `auto_allow_audit` → `clarify_then_retry` → `openclaw_approval` →
`block`。完整且低风险的匹配可自动放行并审计；低影响且最多两个字段缺失时先澄清；
高影响或未知外部目标交给审批；硬风险始终 `block`。hard-block precedence 适用于
规则、风险图和 RV 的所有覆盖层：任何上层只能提升严重性，不能降低既有 block。

`principal`、`agent_id` 和 `capability_lineage` 不得因文本相似而合并；缺失身份只能
得到不确定证据，不能产生自动放行。策略 bundle 按 `policy_version` 版本化，发布前
是 versioned bundle，验证 catalog、rules、relations、traces 和 vectors；出现校验错误或身份状态合并异常，
rollback 到 previous catalog，同时保留全部 audit records。
这些 personal-office scope 只授予完成当前任务所需的最小能力，并随目的、期限和资源
边界记录。
