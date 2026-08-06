# NL 驱动自动机生成与运行时验证升级方案

> 版本：v0.1 | 日期：2026-08-05 | 状态：调研阶段  
> 关联文档：[rv-layer-analysis.md](../features/rv-layer-analysis.md)、[semantic/method.md](../semantic/method.md)、[architecture/refactoring-plan.md](../architecture/refactoring-plan.md)

---

## 一、方案背景与目标

### 1.1 当前架构

OpenClaw-RVGuarder v0.3.0 的安全判定链路为四层流水线：

```
用户输入(chat/hook)
  → BehaviorEvent
  → SemanticEnhancer ──semantic{labels, scenario}──→ DetectionEngine (47条标签谓词)
  │                 └─rv_trace{props}─────────────→ RV引擎 (6个手写ChainRule FSM)
  → Controller (block/ask/allow/escalate)
```

### 1.2 当前局限

| 层次 | 当前能力 | 局限 |
|---|---|---|
| **语义理解** | LLM 贴标签（7 维度扁平 labels），实体/约束被丢弃 | 无实体级语义，无置信度门控，`rv_trace` 只传 `props` 标签 |
| **规则匹配** | 47 条 `tag in labels` 布尔 lambda | 无法表达实体条件（如"收件人域名 != internal"），无置信度加权 |
| **RV 引擎** | 手写 `rv_rules.json` → `_SpecDrivenMonitor` FSM + 窗口管理器 | 规约手写，6 监视器无参数化切片，无法按实体做 per-binding 判定 |
| **干预层** | block/ask/allow/escalate 四级 | 无"带修正建议的 revision"机制，无会话级状态追踪 |

### 1.3 目标架构

以**自然语言输入 → 语义理解（NL2Spec）→ 受限规则匹配 → 自动生成自动机 → 运行时验证**为核心线索，将四层全部升级：

```
自然语言安全策略
  │
  ├─ 语义理解层 ──── NL2Spec 翻译 → 结构化 ToolCallIR（含实体+约束+置信度）
  │
  ├─ 规则匹配层 ──── 4 类约束推理引擎（实体/敏感度/时序/副作用）+ 置信度门控
  │
  ├─ RV 自动机层 ─── 三模型融合：基线自动机(白) + 策略自动机(黑) + NL2Spec 生成
  │
  └─ 干预层 ──────── NEXUS 式 4 级干预：allow / block / confirm / revise
```

---

## 二、分层升级详述

### 2.1 语义理解层：从「贴标签」到「结构化 Plan IR」

**对标文献：NEXUS (arXiv 2607.19356) — Structured Plan IR for Tool-Using Agents**

#### 2.1.1 当前状态

[semantic_enhancer.py](../../openclaw_guard/engine/semantic_enhancer.py) 通过 DeepSeek LLM 调用提取语义标签，但输出格式扁平：

```python
# 当前输出
{
  "semantic": {"scenario": "mail_send", "labels": ["mail_send", "external_recipient"], ...},
  "rv_trace": [{"step_id": "s1", "event": "mail_send", "props": ["mail_send", "external_recipient"]}]
}
```

LLM prompt 中已要求提取的 `entities`（收件人/路径/URL）、`constraints`（时间范围/排除条件）、`confidence` 在 `_build_rv_trace()` 中被丢弃，仅保留扁平 `props` 标签。

#### 2.1.2 升级目标：ToolCallIR

借鉴 NEXUS 的 Structured Plan IR，输出完整结构化的工具调用描述：

```python
from dataclasses import dataclass, field
from enum import StrEnum

class PermissionLevel(StrEnum):
    READ_ONLY = "read_only"
    USER = "user"
    ELEVATED = "elevated"
    SUDO = "sudo"

class SideEffect(StrEnum):
    NONE = "none"
    WRITE_LOCAL = "write_local"
    NETWORK_EGRESS = "network_egress"
    CONFIG_MUTATE = "config_mutate"
    DESTRUCTIVE = "destructive"

class Irreversibility(StrEnum):
    REVERSIBLE = "reversible"
    PARTIALLY_REVERSIBLE = "partially_reversible"
    IRREVERSIBLE = "irreversible"

class IntentClass(StrEnum):
    BUSINESS_TASK = "business_task"
    EXPLORATION = "exploration"
    MAINTENANCE = "maintenance"
    ANOMALY = "anomaly"

@dataclass
class Entity:
    kind: str           # "recipient" | "file_path" | "url" | "api_endpoint"
    value: str          # 实体值
    sensitivity: str    # "public" | "internal" | "confidential" | "secret"
    attributes: dict = field(default_factory=dict)

@dataclass
class Constraint:
    type: str           # "time_range" | "scope" | "exclusion"
    value: str | dict

@dataclass
class ToolCallIR:
    """NEXUS Plan IR 的本地方言版"""
    tool_name: str
    arguments: dict
    permission_level: PermissionLevel
    side_effect: SideEffect
    sensitivity_indicators: list[str]
    irreversibility: Irreversibility
    entities: list[Entity]
    constraints: list[Constraint]
    intent: IntentClass
    confidence: float          # 语义理解置信度 0.0-1.0，用于门控决策
    labels: list[str]          # 保留向后兼容
    rv_props: list[str]        # 保留向后兼容
```

**LLM Prompt 改造**：要求 LLM 输出符合 Pydantic 校验的结构化 JSON（而非自由格式），并加入 few-shot 示例确保一致。

#### 2.1.3 置信度门控

来自 NEXUS 的 calibrated risk scoring 和 IntentionReasoner 的多级分类思路：

```
confidence >= 0.8  → 正常判定
0.5 <= c < 0.8    → 降级处理（如 block→escalate, ask→verify）
c < 0.5           → 回退到保守策略（fallback）
```

#### 2.1.4 参考文献

- **[NEXUS]** "Structured Runtime Safety for Tool-Using LLM Agents", arXiv 2607.19356v1, 2026.  
  贡献：Structured Plan IR（6 维工具调用描述）、calibrated risk scoring、4 级干预体系。
- **[IntentionReasoner]** "Facilitating Adaptive LLM Safeguards through Intent Reasoning and Selective Query Refinement", arXiv 2508.20151, 2025.  
  贡献：多级安全分类（4 级 CU/BU/BH/CH）+ 意图推理 + 选择性查询精修。
- **[PARSE]** "LLM Driven Schema Optimization for Reliable Entity Extraction", EMNLP 2025 Industry Track.  
  贡献：LLM 输出 schema 优化方法论，用 Pydantic 强约束保证提取质量。

---

### 2.2 规则匹配层：从「标签交集」到「约束推理引擎」

**对标文献：G-SPEC (arXiv 2512.20275) — Graph-Symbolic Policy Enforcement**

#### 2.2.1 当前状态

[detection.py](../../openclaw_guard/engine/detection.py) 的 `_semantic_predicates()` 为 47 条 `lambda`，本质是标签集合的布尔交集：

```python
("CMD-001", lambda event, labels, scenario: "command_rm_rf" in labels)
("FILE-001", lambda event, labels, scenario: event.action_type == "file_delete" and "path_system_root" in labels)
```

无法表达实体级条件、无法利用置信度、无法跨事件关联。

#### 2.2.2 升级目标：4 类约束推理引擎

借鉴 G-SPEC 的 SHACL 策略框架（拓扑/资源/状态/时序四类约束），用结构化 `Constraint` 对象替代 lambda：

```python
from dataclasses import dataclass
from typing import Callable

class VerdictAction(StrEnum):
    ALLOW = "allow"
    BLOCK = "block"
    ASK = "ask"
    ESCALATE = "escalate"
    REVISE = "revise"  # NEXUS 式：带修正建议的拒绝

@dataclass
class Verdict:
    action: VerdictAction
    reason: str
    revision_hint: str | None = None  # REVISE 时提供修正建议

@dataclass
class ConstraintRule:
    rule_id: str
    title: str
    description: str
    
    # 四类约束（对应 G-SPEC）
    action_constraint: str | None       # action_type 匹配
    entity_constraints: list[EntityConstraint]  # 实体条件
    sensitivity_constraint: SensitivityConstraint | None  # 敏感度条件
    temporal_constraint: TemporalConstraint | None  # 时序条件
    
    verdict: Verdict
    confidence_threshold: float = 0.7   # 置信度门控
    cooldown_seconds: int = 0           # 同规则触发冷却

# 四类约束的数据结构
@dataclass
class EntityConstraint:
    kind: str           # "recipient" | "file_path" | "url"
    match_type: str     # "equals" | "prefix" | "domain_in" | "domain_not_in" | "regex"
    values: list[str]
    negate: bool = False

@dataclass
class SensitivityConstraint:
    min_level: str      # "internal" | "confidential" | "secret"
    min_irreversibility: str  # "reversible" | "irreversible"
    require_indicators: list[str]  # ["contains_pii", "financial_data"]

@dataclass  
class TemporalConstraint:
    type: str           # "rate_limit" | "gap_since_last" | "within_window"
    max_count: int | None
    within_seconds: int
    scope: str          # "per_session" | "per_entity" | "global"
```

**规则示例对比**：

```python
# 旧: 标签匹配
("NET-005", lambda e, labels, s: e.action_type == "network_egress" and "network_secret_payload" in labels)

# 新: 结构化约束
ConstraintRule(
    rule_id="NET-005",
    title="阻断敏感外传",
    action_constraint="network_egress",
    sensitivity_constraint=SensitivityConstraint(
        min_level="confidential",
        require_indicators=["contains_secret", "contains_token"],
    ),
    entity_constraints=[
        EntityConstraint(kind="recipient", match_type="domain_not_in", values=["internal.com", "partner.org"]),
    ],
    verdict=Verdict(action="block", reason="携带凭据外发到外部域"),
    confidence_threshold=0.7,
)
```

#### 2.2.3 约束引擎实现

```python
class ConstraintEngine:
    def evaluate(self, ir: ToolCallIR) -> list[tuple[ConstraintRule, float]]:
        """返回所有命中的规则及其匹配置信度"""
        matches = []
        for rule in self.rules:
            score = self._match_score(rule, ir)
            if score >= rule.confidence_threshold:
                matches.append((rule, score))
        return matches
    
    def _match_score(self, rule: ConstraintRule, ir: ToolCallIR) -> float:
        scores = []
        if rule.action_constraint:
            scores.append(1.0 if ir.tool_name == rule.action_constraint else 0.0)
        for ec in rule.entity_constraints:
            scores.append(self._entity_score(ec, ir.entities))
        if rule.sensitivity_constraint:
            scores.append(self._sensitivity_score(rule.sensitivity_constraint, ir))
        if rule.temporal_constraint:
            scores.append(self._temporal_score(rule.temporal_constraint))
        return sum(scores) / len(scores) if scores else 0.0
```

#### 2.2.4 参考文献

- **[G-SPEC]** "Graph-Symbolic Policy Enforcement and Control: A Neuro-Symbolic Framework for Safe Agentic AI", arXiv 2512.20275v1, 2025.  
  贡献：SHACL 4 类约束（拓扑/资源/状态/时序），规则爆炸问题的图式解决方案。
- **[AutoSafeLTL]** "AutoSafeLTL: Automated Generation of Safe LTL Specifications", arXiv 2503.15840, 2025.  
  贡献：语言包含检查 + 反例引导修正，可作为约束引擎的规则验证机制。
- **[ConformalNL2LTL]** "Conformal Prediction for Natural Language to LTL Translation", arXiv 2504.21022, 2025.  
  贡献：保形预测提供统计正确性保证，对置信度门控设计有参照价值。

---

### 2.3 RV 自动机层：三模型融合自动机

**对标文献：Automata from Agent Traces (2026.06) / QEA-MARQ / TAG**

> 注：RV 层已明确不走 LTL 路线，详见 [rv-layer-analysis.md §5.1](../features/rv-layer-analysis.md)。原因：LTL 语义基于无限序列（ω-自动机），与项目有限滑窗场景不匹配；LTL 参数绑定有组合爆炸风险；引入 Spot/Owl 破坏轻量纯 Python 定位。

#### 2.3.1 三模型架构

```
                      ┌─────────────────────────────────┐
                      │         RV 协调裁决层            │
                      │   判定策略：级联 / 投票 / 加权   │
                      └─────────────────────────────────┘
                          │          │           │
               ┌──────────▼──┐ ┌────▼─────┐ ┌──▼──────────┐
               │ 行为基线     │ │ 安全策略  │ │ NL2Spec 生成 │
               │ 自动机(白)   │ │ 自动机(黑)│ │ 自动机(定制) │
               ├─────────────┤ ├──────────┤ ├─────────────┤
               │ 来源: 审计   │ │ 来源:     │ │ 来源: 用户NL │
               │      日志   │ │ rv_rules  │ │     策略输入 │
               │ 方法: φ抽象  │ │ .json    │ │ 方法: NL2Spec│
               │  +前缀树     │ │ 方法:     │ │ +Spec校验   │
               │  +状态合并   │ │ compile_  │ │             │
               │ 语义: 统计   │ │ monitors  │ │ 语义: 自定义 │
               │      异常    │ │ 语义: 规则 │ │     安全策略 │
               │ 维护: 自动   │ │     违规   │ │ 维护: 声明式 │
               │      更新    │ │ 安全团队  │ │      管理    │
               └─────────────┘ └──────────┘ └─────────────┘
```

#### 2.3.2 自动机一：行为基线自动机（白模型）— 从 trace 推断

完全借鉴 **Automata from Agent Traces** 的管线：

```
审计日志 session traces
  │
  ├─ ① φ 确定性抽象
  │   每个 RvTraceStep → (event_type, entity_kind, label_class) 三元组
  │   例: [mail_recv, file_read, mail_send] → [recv_int, attach_open, send_ext]
  │
  ├─ ② 前缀树构建 (Prefix Tree)
  │   所有正常办公 session 的 trace 合并为共享前缀树
  │
  ├─ ③ 结构合并 (Structural Merging)
  │   频率驱动的状态合并：出现频次相近的子树合并
  │   或 EDSM（Evidence-Driven State Merging）：搜索最佳合并方案
  │
  └─ ④ 输出紧凑 DFA
      描述"正常办公行为的合法路径"
      运行时：当前 trace 在 DFA 接受状态 = 正常；偏离到未定义转换 = 异常
```

**关键属性**（来自 ASG 论文数据）：
- 收敛只需百分之几的训练数据
- 自动机比原始 trace 小 1-3 个数量级
- 三种合并方法（RPNI/EDSM/频率）结果高度一致

**对 OpenClaw 办公场景的适配**：

| 办公场景 | 正常基线路径 | 异常偏离 |
|---|---|---|
| 邮件操作 | read → compose → send（或 delete/archive） | read → forward_external → send（跳过 compose 直转外部） |
| 文件操作 | open → edit → save → close | open → download_bulk → 无 save → 无 close |
| 日历操作 | check → create_event → invite_internal | check → create_event → invite_external_list |
| 搜索操作 | search → open_result → read | search → open_all → download_all |

#### 2.3.3 自动机二：安全策略自动机（黑模型）— 当前 FSM 升级

当前 `_SpecDrivenMonitor` 方案保留，升级三项：

**a) QEA 式参数化切片**（来自 MARQ/QEA）：

```python
# rv_rules.json 扩展
{
  "quantifier": "forall",           # forall | exists
  "bind_vars": ["recipients"],      # 绑定变量，per-binding 创建独立监视器实例
  "chain_rules": [...]
}
```

运行时：`trace` 按 `bind_vars` 的值切片 → 每个绑定值独立跑 FSM → QEA 量化判定。

**b) TAG 式时钟约束**（来自 TAG AAAI 2022）：

```python
# StepRequirement 扩展
{
  "step_gap_within_seconds": 60,  # 两步间隔 ≤60s
  "step_gap_at_least_seconds": 10  # 两步间隔 ≥10s（防止瞬间链）
}
```

**c) 实体级守卫**：

```python
{
  "entity_any_of": [
    {"kind": "recipients", "match": "domain_in", "values": ["external.com"]}
  ]
}
```

#### 2.3.4 自动机三：NL2Spec 生成自动机

完整管线：

```
用户 NL 安全策略输入
  │
  ├─ ① LLM QA 分解翻译（ConformalNL2LTL 式）
  │   Q1: 规则涉及哪些事件步骤？
  │   Q2: 参与判定的实体/约束？
  │   Q3: 违规时 verdict？
  │   → 输出 ChainRule IR + 回映射（source_nl 字段）
  │
  ├─ ② SpecValidator 确定性校验（AutoSafeLTL 式）
  │   a. 语法校验：Pydantic Ruleset 解析
  │   b. 反例注入：正/负例 trace 库跑生成监视器
  │      - 漏报 → 攻击链未被拦 → 反例喂回 LLM 修正
  │      - 误报 → 合法链被拦 → 反例喂回 LLM 修正
  │   c. 冲突检测：与现有规则集做 from+when 去重
  │
  ├─ ③ compile_monitors() 编译 → _SpecDrivenMonitor FSM
  │
  └─ ④ 合并至 rv_rules.json（标记 origin: "nl2spec"）
```

**LLM 不直接生成 JSON**：LLM 负责提取意图和约束（QA 分解），确定性代码负责将结构化 IR 编译为 ChainRule。遵循 Auto-Claude 的架构原则：**状态不可由概率组件控制**。

#### 2.3.5 RV 引擎架构参数

| 参数 | 说明 | 默认值 |
|---|---|---|
| `window_max_size` | 滑动窗口最大步数 | 10 |
| `window_ttl_seconds` | 滑动窗口 TTL | 300 |
| `baseline_update_interval` | 基线自动机重训间隔 | 3600 |
| `verdict_strategy` | 三模型裁决策略 | cascade（级联：白放行→黑拦截→定制增强） |
| `qea_bind_limit` | QEA 参数绑定最大实例数 | 100 |

#### 2.3.6 参考文献

- **[ASG]** Cho et al., "Automata from Agent Traces", Holistic AI + UCL, 2026.06.  
  链接: https://seongland.com/article/asg | 论文: https://openreview.net/forum?id=1cprFkvFT0  
  贡献：从 agent trace 自动生成监视自动机的完整管线（φ抽象→前缀树→状态合并→FSM），收敛极快（百分之几数据），四种用途统一（记忆/预测/失败检测/RV 监视）。
- **[QEA-MARQ]** Barringer et al., "Quantified Event Automata: Towards Expressive and Efficient Runtime Monitors", FM 2012 / RV 竞赛 2014-2016 冠军.  
  链接: https://github.com/selig/qea | 论文: https://www.cs.man.ac.uk/~regerg/papers/marqOverview.pdf  
  贡献：参数化 trace 切片（per-binding 监视器实例）+ QEA 量词（∀/∃）+ 结构特化优化。
- **[TAG]** Cornanguer et al., "TAG: Learning Timed Automata from Logs", AAAI 2022.  
  贡献：从日志学习确定性时间自动机，单参数，带显式时钟约束。
- **[NL2Spec]** Hahn et al., "nl2spec: Interactively Translating Unstructured Natural Language to Temporal Logics with LLMs", CAV 2023.  
  贡献：子公式回映射 + human-in-the-loop 迭代精修。
- **[VLTL-Bench]** arXiv 2507.00877, 2025.  
  贡献：NL→LTL 翻译的四步法基准（lifting→grounding→translation→verification），可复用于 NL→ChainRule 验证。
- **[Auto-Claude FSM]** community discussion, 2025.  
  贡献：架构原则 — 概率组件（LLM）不控制状态，状态由确定性引擎管理。

---

### 2.4 干预层升级：NEXUS 式 4 级干预

#### 2.4.1 从 4 级到 4+1 级

```
当前:   allow → ask → escalate → block
升级后: allow → confirm → revise → escalate → block
```

**新增 `revise`**：拒绝执行但附带修改建议（如"已移除外部收件人，是否发送仅内部版本？"），对应 NEXUS 的 `request_revision`。

#### 2.4.2 会话级状态追踪

借鉴 IntentionReasoner 的多轮上下文理解：

```python
@dataclass
class SessionSafetyState:
    session_id: str
    risk_score: float            # 累积风险分
    blocked_count: int           # 已拦截次数
    escalation_level: int        # 干预升级级别
    last_intervention: str       # 最近一次干预类型
    intervention_history: list   # 干预历史
```

连续 `ask` 可自动升级为 `escalate`，连续 `escalate` 可自动升级为 `block`。

---

## 三、OpenClaw 个人办公场景攻击面与覆盖

| 攻击类型 | 攻击链示例 | v0.3.0 覆盖 | 升级后覆盖 |
|---|---|---|---|
| **数据外泄** | 读内部文件 → 摘要提取 → 外发邮件 | RV 部分（MailMonitor） | 基线自动机检测"正常写邮件"和"异常复制+转发"差异 |
| **工具误用链** | 搜索通讯录 → 导出全部 → 写入草稿 → 群发 | 静态规则不够 | QEA 参数化切片 per-recipient |
| **越权操作** | 修改权限脚本 → sudo → 读他人文件 | 无覆盖 | QEA ∀file: 写权限变更后跨用户读 |
| **Prompt 注入 via Tool** | 网页内容 → 摘要工具含注入 → 传给下步工具 | 无覆盖 | 基线自动机: 正常"网页→摘要→回复"方向性可检测注入 |
| **供应链插件风险** | 安装 MCP 插件 → 请求文件权限 → 静默上传 | 无覆盖 | 基线自动机: 插件安装后首次行为偏离告警 |
| **批量外发** (Broadcast) | 正常发日报 → 改收件人为全公司 → 群发 | RV 已有 BroadcastMonitor | NL2Spec 生成"含机密日报禁止群发"自定义规则 |

---

## 四、分阶段实施路线

| 阶段 | 内容 | 依赖 | 参考 |
|---|---|---|---|
| **A: IR 结构化** | `ToolCallIR` 数据模型 + `semantic_enhancer` prompt 改造 → 保留向后兼容 | 无 | NEXUS |
| **B: 约束引擎** | `ConstraintRule` DSL + `ConstraintEngine` 替换 47 条 lambda | A | G-SPEC |
| **C: RV 基线** | `BaselineLearner`（φ抽象+前缀树+状态合并）+ `BaselineMonitor`（DFA 判定） | A | ASG |
| **D: RV 参数化** | QEA 式 `bind_vars` + `entity_all_of` 守卫 + TAG 式 `step_gap` | A | MARQ / TAG |
| **E: NL2Spec** | `Nl2SpecGenerator`（QA 分解 + ChainRule 合成）+ `SpecValidator`（反例闭环） | D | NL2Spec / AutoSafeLTL |
| **F: 干预升级** | `revise` 干预 + `SessionSafetyState` 会话追踪 | B | NEXUS / IntentionReasoner |

---

## 五、关键设计原则

1. **LLM 提议，确定性引擎裁决**（Auto-Claude 原则）：LLM 生成候选规约 / 提取实体，不直接控制状态。所有生效判定由 `ConstraintEngine` + `_SpecDrivenMonitor` 确定性执行。
2. **向后兼容**：所有新字段设为可选，`labels` / `props` 保留以兼容现有 47 条规则和 6 个监视器。
3. **细粒度单一职责**（NL-to-LTL scaling law 教训）：每个监视器规则 ≤5 步，每个约束 ≤3 个实体条件，避免 LLM 精度随复杂度衰减。
4. **纯 Python 零重量依赖**：不引入 C++/Java 运行时，所有算法纯 Python 实现。

---

## 六、参考文献总目

| 编号 | 文献 | 出处 | 链接 | 核心关联 |
|---|---|---|---|---|
| [1] | **NEXUS**: Structured Runtime Safety for Tool-Using LLM Agents | arXiv 2607.19356, 2026 | https://arxiv.org/abs/2607.19356 | 语义理解 IR + 干预体系 |
| [2] | **G-SPEC**: Graph-Symbolic Policy Enforcement and Control | arXiv 2512.20275, 2025 | https://arxiv.org/abs/2512.20275 | 规则匹配 4 类约束 |
| [3] | **ASG**: Automata from Agent Traces | Holistic AI + UCL, 2026.06 | https://seongland.com/article/asg | RV 基线自动机 |
| [4] | **MARQ**: Monitoring At Runtime with QEA | RV 竞赛 2014-2016 冠军 | https://github.com/selig/qea | RV 参数化切片 |
| [5] | **TAG**: Learning Timed Automata from Logs | AAAI 2022 | https://ojs.aaai.org/index.php/AAAI/article/view/20528 | RV 时间自动机 |
| [6] | **NL2Spec**: Interactively Translating NL to Temporal Logics | CAV 2023 | https://github.com/realChrisHahn2/nl2spec | NL→规约翻译 |
| [7] | **AutoSafeLTL**: Automated Generation of Safe LTL Specifications | arXiv 2503.15840, 2025 | https://arxiv.org/abs/2503.15840 | 规约验证闭环 |
| [8] | **ConformalNL2LTL**: Conformal Prediction for NL-to-LTL | arXiv 2504.21022, 2025 | https://arxiv.org/abs/2504.21022 | 置信度门控 |
| [9] | **IntentionReasoner**: Intent Reasoning and Selective Query Refinement | arXiv 2508.20151, 2025 | https://arxiv.org/abs/2508.20151 | 意图推理 + 多级分类 |
| [10] | **VLTL-Bench**: Benchmark for NL to LTL Translation | arXiv 2507.00877, 2025 | https://arxiv.org/abs/2507.00877 | 翻译验证基准 |
| [11] | **PARSE**: LLM Driven Schema Optimization for Entity Extraction | EMNLP 2025 Industry | https://aclanthology.org/2025.emnlp-industry.184.pdf | LLM 结构化输出 |
| [12] | **Learn, Check, Test**: Security Testing Using Automata Learning | arXiv 2509.22215, 2025 | https://arxiv.org/abs/2509.22215 | 自动机学习+安全验证 |
| [13] | **NL-to-LTL Scaling Law**: Systematic Evaluation of LLM Translation | arXiv 2606.30163, 2025 | https://arxiv.org/abs/2606.30163 | 细粒度规则设计依据 |
| [14] | **Structure/Event-Driven SMF**: LLM for State Machine Generation | arXiv 2604.00275, 2025 | https://arxiv.org/abs/2604.00275 | guards F1=0.23 教训 |
| [15] | **Parametric Trace Slicing** | TACAS 2009, Chen & Roşu | https://doi.org/10.1007/978-3-642-00768-2_23 | 参数化 trace 理论基础 |
