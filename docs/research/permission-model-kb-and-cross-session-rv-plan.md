# OpenClaw-RVGuarder 权限模型知识库与跨会话运行时验证最终方案

**研究日期：** 2026-08-25
**状态：** 融合升级版（含规则匹配优化与权限组合决策模型）
**研究对象：** OpenClaw-RVGuarder 当前代码与 OpenClaw 审批交接链
**来源：** DeepSeek 研究方案与 `agent-permission-rv-research-report-2026-08-25.md` 的对比、批判和融合

> **阅读边界：** 本文是研究与方案记录，不是逐项代码接口合同。当前实现以
> [`project-memory.md`](../architecture/project-memory.md)、
> [`permission-kb-runtime-architecture.md`](../architecture/permission-kb-runtime-architecture.md)
> 和代码为准；本文中的 `revise`、旧规则数量和早期攻击基线均保留原研究语境。

关联文档：[RV 权限自动机架构](../architecture/rv-permission-automata.md)、[办公场景矩阵](../semantic/office-scenario-matrix.md)；研究实施计划的历史执行记录位于 `docs/archive/plans/2026-08-25-agent-permission-rv-research-plan.md`。

## 1. 执行摘要

本项目已有“语义增强 → 约束推理 → 规则检测 → RV/FSM → OpenClaw 原生审批”的雏形，但安全边界仍停留在事件和标签层。两份研究报告的共同结论是：下一阶段的核心不是继续堆叠关键词，而是建立一个可审计、可版本化、可计算权限闭包的权限语义层，并让运行时验证消费这一层。

最终方案形成三条相互闭环的主线：

1. **权限模型知识库（PMKB）**：把工具调用标准化为权限、资源、作用域、数据分类、主体和能力谱系；每个有副作用的 trace 步骤必须得到规则覆盖或显式缺口结论。
2. **权限关系与运行时验证**：计算当前有效权限闭包、申请权限差分、冗余/扩张/冲突和危险组合；保留现有时序 FSM，增加稀疏权限状态、事件溯源和跨会话监控。
3. **攻击基准与必要性验证**：把间接提示注入、敏感数据外传、权限膨胀、跨 session 数据流和技能供应链等案例转成安全的本地权限 trace，比较改造前后漏报、误报、覆盖率和延迟。

最终决策仍由确定性策略、权限关系和 RV 监视器完成；LLM 只负责结构化抽取、候选规则生成和语义召回。未知或高影响且未覆盖的请求不得静默放行。

## 2. 两份报告的比较与批判

### 2.1 DeepSeek 方案的有效贡献

- 明确提出将当前硬编码 ConstraintRule 数据化为 Permission Model Knowledge Base（PMKB）。
- 把 `implies`、`conflicts`、`dangerous_combo` 和最小权限判定引入权限关系模型，弥补单步标签匹配不能表达组合风险的问题。
- 使用 QEA/参数化切片解释跨会话监视，说明同一业务目标上的多个 session 可以共享一个监视器实例。
- 给出 EchoLeak、MCP 供应链、Clinejection、Agent Session Smuggling 等攻击案例，便于建立反例基准。

### 2.2 DeepSeek 方案需要修正的地方

1. **不能显式实现 `Q=2^P`。** 这是形式化说明，不是工程数据结构。生产实现应使用稀疏权限集合、蕴含闭包和危险组合超边索引，否则权限数量增长会导致状态爆炸。
2. **`goal_id` 不能单独作为安全身份。** 它适合做任务分区，但模型推断的目标名可能错误或被污染。跨 session 合并必须校验可信 principal、agent 和 capability lineage；无法校验时应隔离或升级。
3. **“当前 FSM 完全无法捕获 EchoLeak”过于绝对。** 当前 `SecurityChainMonitor` 对“敏感读取 → 外发”已有部分覆盖。真正缺失的是通用权限组合、参数语义、身份谱系和跨 session 状态，不能把已有能力误删。
4. **向量检索不能成为授权依据。** embedding 只能召回候选规则；权限 ID、作用域、否定条件和最终决策必须由确定性 schema 和规则评估器确认。
5. **部分攻击情报需要证据分级。** NVD、论文和厂商公告可作为一手/高可信材料；博客、预印本和未来日期的案例必须标为待复核，不能直接宣称本项目已复现。

### 2.3 本项目研究报告补强的内容

- 用 RBAC + ABAC + ReBAC + Capability 的混合模型补充 PMKB 的主体、资源、关系和委派语义。
- 给出 `Authorization Trace`、规则 evidence、coverage/gap、confidence 和 provenance，解决“命中规则但无法证明覆盖”的审计问题。
- 将运行时结论扩展为 `allow / ask / block / revise`，并明确 `inconclusive` 不能静默当作安全。
- 提出主体/Agent/能力 lineage 的全局状态、快照和重放，而不是简单扩大 session 窗口。
- 已建立安全本地攻击夹具和当前 FSM 基线：AT-01 已被现有链路升级，AT-02～AT-08 暴露权限闭包、组合和跨 session 缺口。

### 2.4 融合后的原则

| 原则 | 最终选择 |
|---|---|
| 知识库 | JSON/YAML + 确定性索引；向量检索仅作候选召回 |
| 权限模型 | RBAC/ABAC/ReBAC/Capability 混合，工具名不直接等于权限 |
| 自动机 | 保留现有事件 FSM，叠加稀疏权限状态和危险组合超边 |
| 跨 session | `goal_id` 优先做任务分区，同时强制 principal/agent/capability lineage 校验 |
| LLM | 结构化抽取和候选生成，不直接作最终授权 |
| 外部依赖 | 首期不引入 OPA/Cedar/MonPoly 作为在线强依赖，吸收其模型与验证思想 |
| 历史材料 | 保留两份原始报告、研究计划、实验夹具和历史产物 |

## 3. 当前代码基线与主要缺口

### 3.1 已有能力

| 位置 | 当前能力 | 可复用价值 |
|---|---|---|
| `openclaw_guard/rv/ir.py` | `ToolCallIR` 含 tool、arguments、permission、sensitivity、irreversibility、intent 等字段 | 可扩展为 Authorization Trace，无需重建传输层 |
| `openclaw_guard/rv/constraints.py` | action/tag/entity/sensitivity/temporal 五类约束；10 条 `migrated_constraint_rules()` 数据规则 | 可保留为局部谓词引擎，增加证据和组合层 |
| `openclaw_guard/rv/rv_dsl.py`、`rv_monitors.py` | ChainRule、FSM、序列与参数化原语 | 继续表达时序安全属性 |
| `openclaw_guard/rv/runtime_verification.py` | per-session window、TTL、序列化/反序列化、监视器隔离 | 是跨 session 状态持久化的基础 |
| `openclaw_guard/spec/session_state.py` | 风险累积、ask→escalate、escalate→block、revision hint | 可扩展为主体/能力 lineage 风险状态 |
| `openclaw_guard/spec/nl2spec_generator.py` | 关键词模板和 `use_llm` 接口 | 需要接入 schema 校验和 PMKB 引用校验 |

### 3.2 关键缺口

1. 事件能描述“调用了什么”，但不稳定描述“谁代表谁、访问什么资源、增加了哪些有效权限、数据从哪里来、将发往哪里”。
2. 当前 ConstraintEngine 对单步声明约束使用 AND 和加权评分，未表达当前权限闭包、请求差分、职责分离和危险组合。
3. 低置信度规则被门控后会从结果中消失，调用方看不到“不确定”与“安全放行”的差异。
4. 当前 RV 主要按 `session_key` 隔离；虽有序列化接口，但还没有贯通持久化、可信主体索引和跨 session 事件聚合。
5. NL2Spec 的 LLM 路径尚未完成，规则生成还不能保证权限引用存在、语义条件可执行或带有正反例。

## 4. 统一权限模型知识库（PMKB）

### 4.1 权限本体

PMKB 采用小而稳定的高频权限词表，先覆盖办公、文件、命令、网络、数据和扩展场景：

| 权限族 | 规范化操作 | 资源/作用域 | 典型风险 |
|---|---|---|---|
| 文件 | `file.read/write/delete` | workspace 内外、敏感路径、批量范围 | 敏感读取、破坏、持久化 |
| 命令 | `process.execute` | 命令 AST、工作目录、继承环境 | 提权、横向、破坏性执行 |
| 网络 | `network.connect/egress` | 域名/IP、端口、协议、外部区 | 数据外发、未授权访问 |
| 通信 | `message.send/email.send` | 收件人、群组、频道、附件 | 外部域、群发、不可撤回 |
| 数据 | `data.query/export` | 数据集、字段、行数、脱敏状态 | PII/secret 批量导出 |
| 凭据 | `secret.read/use` | token、密钥、环境变量 | 高敏感泄露、提权 |
| 配置 | `config.modify/audit.modify` | OpenClaw 配置、规则、审计开关 | 持久化、绕过监控 |
| 扩展 | `skill.install/run` | 来源、依赖、工具集合 | 供应链、过度授权 |

每个 Permission 至少包含：`id`、`verb`、`resource_type`、`scope`、`effect`、`sensitivity`、`irreversibility`、`criticality`、`requires_approval`、`default_effect`。

Capability 描述工具、Agent 或 skill 可提供的权限集合，并记录 `default_deny`、签发者、TTL、目的和父能力。Relation 至少支持：

- `implies(p, q)`：强权限蕴含弱权限；
- `conflicts(p, q)`：互斥或职责冲突；
- `toxic_with({p1, p2, ...})`：组合后进入危险态；
- `delegates(parent, child)`：委派能力谱系；
- `owns(principal, resource)`：主体与资源关系。

### 4.2 存储与检索

知识库分四层：

1. **Ontology**：操作、资源、主体、属性、数据分类、同义词和反例。
2. **Policy**：版本化确定性规则、适用范围、有效期、效果和义务。
3. **Relationship graph**：角色继承、skill 能力、资源所有权、委派和 lineage。
4. **Evidence/test set**：规则来源、正例、反例、边界例、语义改写和回归结果。

检索采用“精确索引优先 + 同义词/别名 + 可选向量召回”。每一步 trace 输出 `matched_rules`、`gaps`、`conflicts`、`uncertainties` 和 `coverage`。任何高影响步骤没有覆盖时，不得静默 `allow`。

### 4.3 Authorization Trace

保持旧 `ToolCallIR` 字段兼容，逐步补充以下结构：

```json
{
  "trace_id": "...",
  "seq": 12,
  "principal": {"type": "human|agent|skill", "id": "..."},
  "agent_id": "...",
  "session_id": "...",
  "goal_id": "...",
  "capability_lineage": ["user-grant-1", "skill-7"],
  "operation": {"family": "data.export", "tool": "...", "arguments": {}},
  "resource": {"type": "document_set", "ids": [], "scope": "workspace"},
  "data": {"classification": "secret", "fields": [], "quantity": 0},
  "context": {"network_zone": "internal", "recipient_domains": []},
  "current_permissions": [],
  "requested_delta": [],
  "provenance": {"source": "user|tool_output|memory|system", "trust": "..."},
  "confidence": {"operation": 0.98, "resource": 0.72, "scope": 0.41},
  "coverage": {"matched_rules": [], "gaps": [], "status": "complete|partial|unknown"}
}
```

规则记录必须附带 `rule_id/version/match/preconditions/effect/obligations/toxic_with/provenance/test_vectors`。这使审批、审计、回放和知识库维护共享同一证据格式。

### 4.4 语义分解与 NL2Spec

```text
输入（用户指令 / 工具调用 / 外部内容 / 记忆）
  → 来源分类与信任标记
  → 主体、动作、资源、范围、条件、目的、收件人抽取
  → 工具与参数归一化为权限族
  → 精确索引和语义召回
  → 每步覆盖/缺口/冲突检查
  → 权限闭包与危险组合判定
  → 确定性策略与 RV 决策
```

LLM 输出必须符合 JSON Schema，并保留字段级置信度、缺失字段和 provenance。引用的 Permission、Relation 和 dangerous combo 必须能在 PMKB 中解析；失败时回退到模板或请求澄清。LLM 不得绕过策略评估器直接调用工具。

推荐门控：

| 情况 | 决策 |
|---|---|
| 高影响、关键字段完整、规则无冲突 | 进入确定性判定 |
| 低风险、范围完整、命中允许规则 | `allow` |
| 高影响但资源/范围/来源未知 | `ask` 或 `revise` |
| 规则冲突、否定/例外无法确认 | `ask` |
| 任一关键步骤无覆盖 | 禁止静默放行 |

## 5. 权限关系、风险分级与运行时验证

### 5.1 当前权限与申请权限

有效权限采用闭包表示：

```text
P_effective = closure(direct_grants ∪ inherited_roles
                      ∪ relationship_edges ∪ active_capabilities
                      ∪ temporary_grants)
ΔP = requested_permissions − P_effective
P_after = closure(P_effective ∪ requested_permissions)
```

判定至少区分：

- **冗余**：请求已被 `P_effective` 覆盖；不增加 grant，但记录 redundancy；
- **权限扩展**：`ΔP` 非空，计算新增资源、数据类别、外部边界和副作用；
- **隐式扩展**：角色、skill 或工具继承使低权限请求获得高权限，按闭包结果判定；
- **作用域扩展**：workspace → outside/external/bulk，至少 `ask`；
- **过期/撤销**：TTL、purpose 或撤销版本失效时拒绝旧 capability；
- **职责冲突**：命中静态/动态职责分离或 toxic set 时 `ask`/`block`。

### 5.2 重要权限分级

风险等级与审批动作分离。项目内部可采用离散排序模型：

```text
risk = impact × exposure × irreversibility × uncertainty
```

其中 impact 反映控制范围，exposure 反映内部/外部边界，irreversibility 反映可恢复性，uncertainty 反映字段和来源不完整程度。该公式是项目内部排序方法，不替代国家标准或组织风险制度。

通常属于 `critical` 的权限包括：`secret.read`、`data.export`、`email.send_external`、`process.execute`、`account.grant`、`config.audit.modify`、未验证来源的 `skill.install`。

### 5.3 危险组合超边

| 组合 | 攻击含义 | 默认控制 |
|---|---|---|
| `secret.read` + `network.egress` + 外部目标 | 凭据/敏感数据外泄 | `block` 或强审批 |
| `data.read` + `data.export` + 外部收件人 | 批量数据外传 | 敏感数据 `block`，其它 `ask` |
| `config.modify` + `audit.modify/disable` | 修改配置并关闭证据链 | `block` |
| `credential.read` + `process.execute` | 凭据驱动提权/横向动作 | `ask`/`block` |
| `skill.install` + 未验证来源 + 高权限工具 | 供应链或工具投毒 | `block` |
| `file.write` + 启动项/持久化 | 持久化 | `block` |
| `approval.bypass` + 任一高影响操作 | 绕过人工控制 | `block` |
| 跨 session 读取 → 外发 | 隐藏数据流 | 以可信 lineage 聚合后升级 |

实现上使用稀疏集合、`implies` 闭包和超边索引，不枚举 `2^P` 全部状态。危险态由权限集合和必要的时间、主体、资源、目的条件共同决定。

### 5.4 保留 FSM，增加多层 RV

不整体替换现有 FSM，而是增加 typed event 和三类状态：

1. **Session monitor**：继续监视同一 session 内的顺序、窗口和数量约束；
2. **Principal/capability monitor**：跨 session 维护有效权限、已接触敏感数据、临时授权、撤销和能力谱系；
3. **Hyperedge monitor**：检测危险组合、数据流和权限差分。

结果使用 `safe / violation / inconclusive` 内部语义，再映射为 `allow / ask / block / revise`。`inconclusive` 不得自动变成 `safe`。事件应带单调序号，配合 snapshot + replay 恢复状态。

### 5.5 `goal_id` 优先的跨 session 模型

本方案采用用户确认的 `goal_id` 优先策略，但把它定义为任务分区键，而不是唯一安全身份：

```text
monitor[goal_id] = sparse_permission_state
```

关联规则：

1. 显式、可信的 `goal_id` 优先；
2. 必须同时校验 principal、agent 和 capability lineage；
3. 只有模型推断出的低置信度 `goal_id` 不得合并高风险状态；
4. `goal_id` 缺失或身份变化时回退到 session 隔离域；
5. revoke、expire、principal 变化和 capability 变化都产生显式事件；
6. 多 worker 部署前使用统一事件日志或共享状态存储，避免内存漂移。

建议的全局安全状态：

```text
GlobalSecurityState
  ├─ principal_id → roles / effective_permissions / revocations
  ├─ capability_id → issuer / parent / expiry / scope / purpose
  ├─ goal_id → sessions / permission_summary / risk_state
  ├─ data_lineage → resource / classification / readers / egress
  └─ event_log + snapshots → seq / replay_hash
```

短期可使用内存索引 + JSON/SQLite snapshot；复杂闭包只在高影响权限或命中候选超边时执行，避免把 LLM 放进 RV 热路径。

## 6. 攻击基准、复现环境与必要性论证

### 6.1 证据边界

OWASP LLM/Agentic 风险分类、AgentDojo、InjecAgent、MELON、NVD EchoLeak 以及官方安全公告支持“外部内容注入可通过高权限工具形成真实攻击链”的必要性判断。但它们不等于本项目已存在相同漏洞。博客、预印本和尚未独立核验的案例须标为研究线索，不作为生产安全结论。

### 6.2 本项目本地攻击矩阵

| ID | 场景 | 主要缺口 | 升级后预期 |
|---|---|---|---|
| AT-01 | 间接注入 → `secret.read` → 外部外发 | 来源可信度、数据流和组合闭包 | 外发前至少 `ask`，敏感组合 `block` |
| AT-02 | 摘要任务却获得 read/write/delete/network | 任务目的与 capability 最小权限 | 只授予 read，其余 excessive |
| AT-03 | 重复申请已有权限，再扩大到外部范围 | delta、冗余和作用域判定 | redundant 不增加 grant，外部范围审批 |
| AT-04 | `credential.read` + `process.execute` 或 `config.modify` + `audit.disable` | 通用 toxic set | 命中超边并升级/阻断 |
| AT-05 | session A 读取，session B 外发 | 跨 session 主体/能力 lineage | 同一可信 lineage 聚合并命中 |
| AT-06 | 否定、例外、内部域和全项目范围改写 | 语义分解和 scope 保真 | 不完整则 `revise/ask` |
| AT-07 | 普通工具名但参数含 delete/egress/credential | 只看工具名 | 参数归一化为真实权限族 |
| AT-08 | skill 声称只读，运行时请求 network/write/install | manifest 与运行时差分 | 超界阻断 |

测试必须完全本地、无网络、无真实凭据。现有 `testlab/research/` 已提供场景 JSON、假资源、只读 fixture 和 baseline adapter。当前基线观察为：AT-01=`escalate`，AT-02～AT-08=`ok`。这说明已有敏感读取—外发链路有效，但权限差分、组合、参数语义和跨 session 仍缺失；它不是完整生产攻击成功率。

每个场景应输出：`baseline_decision`、`upgraded_decision`、`matched_rules`、`gaps`、`trace_fidelity`、`attack_succeeded`、`latency`、`audit_evidence` 和 `replay_hash`。

只有当基线漏报可归因于模型缺口，且升级实现在同一输入、语义改写和顺序扰动下稳定阻止攻击、保持合法任务成功，并满足延迟与审计要求时，才能宣称改造具有必要性和有效性。

## 7. 分阶段实施路线

### P0：权限语义与证据契约

- 建立 `PermissionCatalog`、工具映射、同义词、反例和规则 provenance；
- 扩展 `ToolCallIR` 的主体、资源、作用域、来源、置信度、coverage 字段；
- 保留旧 decision 字段，同时输出 `matched_rules/gaps/uncertainties/conflicts`；
- 将当前 10 条 `migrated_constraint_rules()` 映射为 PMKB 条目；
- 增加 AT-06/AT-07 语义回归。

**退出条件：** 高影响事件关键字段完整率达到项目目标；自动放行的高影响事件必须 `coverage=complete`；旧测试不退化。

### P1：权限差分与危险组合

- 实现 `effective_permissions`、`requested_delta`、`redundant/expanded/expired/conflict`；
- 加入首批 secret+egress、credential+execute、config+audit-disable 超边；
- 在现有审批/审计界面显示新增权限、冗余权限、触发组合和规则证据；
- 不新增第二个审批入口，OpenClaw 仍是最终审批中心。

**退出条件：** AT-02/AT-03/AT-04 通过；权限闭包与离线 oracle 一致；合法只读任务误报可接受。

### P2：持久化与跨 session RV

- 接通现有 `serialize_state`/`deserialize_state` 与 JSON/SQLite snapshot；
- 引入事件序号、快照、重放、TTL 和显式撤销/过期事件；
- 建立 session-local 与 goal/principal/capability-global 分层监视器；
- 身份缺失或谱系不一致时隔离，不以相似文本或工具名合并；
- 完成 AT-05、重启恢复、重复事件和多 worker 一致性测试。

**退出条件：** 定义场景集中的跨 session 漏报为 0；重启前后状态和决策一致；内存和状态保留有上限。

### P3：NL2Spec 与红队发布门禁

- 自然语言策略 → canonical policy IR → DSL；
- 做 schema、权限引用、闭包和冲突校验；
- 自动生成正例、反例、边界例，人工确认后写入 policy store；
- 每次规则变更运行攻击矩阵、合法任务集和性能基线；未通过不得灰度发布。

## 8. 测试与验收标准

### 单元与契约测试

- PMKB schema、版本、规则引用和链接完整性；
- 权限蕴含、冲突、撤销、TTL 和危险组合闭包；
- Authorization Trace 的旧字段兼容、coverage/gap 和 provenance；
- `goal_id`、principal、agent、capability lineage 的隔离与合并规则。

### 运行时回归

- 单 session 时序规则不退化；
- 同一 `goal_id` 跨 session 的连续事件可恢复；
- 不同主体共享 `goal_id` 不得错误合并；
- snapshot/replay、worker 重启、重复事件、状态过期可重现；
- `inconclusive` 必须升级而非静默放行。

### 攻击与性能

- AT-01～AT-08 攻击矩阵对比旧/新结果；
- 同义改写、否定、范围和工具名伪装；
- 合法任务成功率、误报率、规则覆盖率、trace fidelity；
- RV p50/p95/p99 延迟、状态大小和长期内存增长；
- 文档构建、链接检查和 `git diff --check`。

## 9. 风险、边界与未决事项

1. `goal_id` 推断错误会导致错误合并，因此高风险状态必须经过身份谱系校验。
2. 权限闭包仍可能因关系图规模增长变慢，应采用索引、缓存和按需计算。
3. revoke 的级联语义需在 P1 固化：默认采用保守级联撤销，并记录来源。
4. 旧标签规则与 PMKB 将有过渡期双轨运行，必须通过一致性指标治理，不应一次删除历史规则。
5. 多 worker 的共享状态和高可用属于后续部署阶段；在此之前应明确单进程边界。
6. 资源分类、默认未知策略、状态保留时长和 OpenClaw 可信身份字段仍需由项目安全策略确认。

## 10. 参考资料与证据等级

以下链接用于支撑模型、标准和公开攻击事实；具体 CVE/博客内容以访问时的一手页面为准。

### 权限模型与策略工程

1. NIST SP 800-162, ABAC：<https://csrc.nist.gov/pubs/sp/800/162/upd2/final>
2. TC260 基于属性的访问控制模型与管理规范项目：<https://std.samr.gov.cn/gb/search/gbDetailed?id=21E3A7420C84ADB3E06397BE0A0AFBAB>
3. GB/T 43696-2024 零信任参考体系架构：<https://openstd.samr.gov.cn/bzgk/gb/newGbInfo?hcno=C166002FE253A840E56BEBF13B4945E7>
4. NIST RBAC FAQ：<https://csrc.nist.gov/Projects/role-based-access-control/faqs>
5. NIST SP 800-53 AC-5/AC-6：<https://csrc.nist.gov/CSRC/media/Projects/risk-management/800-53%20Downloads/800-53r5/SP_800-53_v5_1-derived-OSCAL.pdf>
6. Zanzibar, USENIX ATC 2019：<https://www.usenix.org/conference/atc19/presentation/pang>
7. Open Policy Agent Rego：<https://www.openpolicyagent.org/docs/policy-language>
8. AWS Verified Permissions/Cedar：<https://docs.aws.amazon.com/verifiedpermissions/latest/userguide/terminology.html>
9. CISA IAM 最佳实践：<https://www.cisa.gov/sites/default/files/2023-12/ESF%20IDENTITY%20AND%20ACCESS%20MANAGEMENT%20RECOMMENDED%20BEST%20PRACTICES%20FOR%20ADMINISTRATORS%20PP-23-0248_508C.pdf>

### 规约生成与运行时验证

10. AgentSpec：<https://arxiv.org/abs/2503.18666>
11. Synthesizing Access Control Policies using LLMs：<https://arxiv.org/abs/2503.11573>
12. AgentVLM：<https://www.sciencedirect.com/science/article/pii/S2214212626000098>
13. Schneider, Enforceable Security Policies：<https://doi.org/10.1145/353323.353382>
14. Basin et al., Enforceable Security Policies Revisited：<https://doi.org/10.1145/2487222.2487225>
15. Quantified Event Automata：<https://doi.org/10.1007/978-3-642-32759-9_7>
16. MarQ/QEA runtime monitoring：<https://doi.org/10.1007/978-3-662-46681-0_55>
17. Saltzer & Schroeder, least privilege：<https://doi.org/10.1109/PROC.1975.9939>
18. Hardy, confused deputy：<https://doi.org/10.1145/54289.871709>

### Agent 攻击与验证

19. OWASP Top 10 for LLM/GenAI：<https://genai.owasp.org/initiatives/top-10-for-llm-and-genai/>
20. OWASP Top 10 for Agentic Applications：<https://genai.owasp.org/2025/12/09/owasp-genai-security-project-releases-top-10-risks-and-mitigations-for-agentic-ai-security/>
21. AgentDojo：<https://proceedings.neurips.cc/paper_files/paper/2024/hash/97091a5177d8dc64b1da8bf3e1f6fb54-Abstract-Datasets_and_Benchmarks_Track.html>
22. InjecAgent：<https://aclanthology.org/2024.findings-acl.624/>
23. MELON：<https://proceedings.mlr.press/v267/zhu25z.html>
24. NVD CVE-2025-32711 EchoLeak：<https://nvd.nist.gov/vuln/detail/CVE-2025-32711>
25. Unit 42 Agent Session Smuggling：<https://unit42.paloaltonetworks.com/agent-session-smuggling-in-agent2agent-systems/>

## 11. 项目文件对应关系

- 权限与 IR 基线：`openclaw_guard/rv/ir.py`、`openclaw_guard/rv/constraints.py`；
- 运行时验证：`openclaw_guard/rv/runtime_verification.py`、`openclaw_guard/spec/session_state.py`；
- NL2Spec：`openclaw_guard/spec/nl2spec_generator.py`；
- 研究与计划：`docs/research/agent-permission-rv-research-report-2026-08-25.md`、`docs/archive/plans/2026-08-25-agent-permission-rv-research-plan.md`；
- 攻击夹具：`testlab/research/scenarios.json`、`testlab/research/fixtures.py`、`tests/test_research_attack_fixtures.py`；
- 现有 RV 路线：`docs/architecture/rv-permission-automata.md`、`docs/ops/roadmap.md`。

本文件是两份研究报告的融合最终版；原始研究报告和实验产物保留用于追溯，不代表其中每一条未经验证的外部攻击描述都已在本项目复现。

## 12. 规则匹配失败根因与降审批方案

### 12.1 现象定义：不要把“未命中”当成“高风险”

当前系统的默认路径是：检测规则未命中后，`_fallback_decision()` 对 `file_delete`、`file_write`、`config_modify`、`network_egress`、`channel_send`、`skill_run` 等敏感动作统一返回 `ask`；Hook 路径的白名单覆盖又受 `_can_whitelist_override()` 限制，仅允许 `chat_message` 覆盖。因此，以下三种状态最终看起来完全相同：

1. **真正高风险**：应阻断或升级；
2. **已知低风险但规则缺失**：应自动放行并审计；
3. **语义不完整/参数无法解析**：应请求补充字段，而不是让审核员重新理解全部上下文。

优化的第一原则是引入三轴结果：

```text
match_status = matched | partial | unknown
security_risk = low | medium | high | critical
decision = allow | ask | block | revise
```

只有 `unknown + high/critical` 才进入人工审批；`matched + low` 走受控自动放行；`partial` 优先生成一条针对缺失字段的澄清请求。

### 12.2 已确认的根因矩阵

| 根因维度 | 当前代码证据 | 直接后果 | 优先级 |
|---|---|---|---|
| 规则覆盖不足 | PMKB 当前包含 28 个操作、35 条 authored 规则和 47 条 `LEGACY-*` 回放记录；仍需补充合法低风险正例与业务目的规则 | 已知动作无法被证明为低风险，落入默认 `ask` | P0 |
| 规则双轨漂移 | DetectionRule 读取 `action_type + match_labels`；ConstraintRule 读取 IR 的 action/tag/entity/sensitivity/temporal；两者没有统一规则 ID、版本和覆盖报告 | 一条路径命中、另一条路径未命中，难以解释也无法统一调参 | P0 |
| 逻辑表述过硬 | Detection 使用 `all(label in labels)`；`TagConstraint.require_all` 是精确集合 AND；没有同义词、可选条件、否定、范围包含和参数谓词 | 输入只要缺一个标签就完全不匹配；自然语言变体全部变成未知 | P0 |
| 特征提取不精准 | 本地语义层主要使用大小写后子串扫描；中文同义词、否定、例外、数量、资源边界和工具参数未形成稳定 AST | “不要外发”“仅内部域”“除日志外”可能被误标或漏标 | P0 |
| 场景分类冲突 | `_infer_scenario()` 按固定 token 顺序判断；邮件读取、发送、报告生成等复合输入可能被先到的场景分支截断 | 正确规则的 action/scenario 维度无法同时满足 | P1 |
| 实体缺失即失败 | `EntityConstraint.matches([])` 恒为 false；没有区分“资源为空”“资源尚未解析”“资源确实不满足” | 收件人、路径和 URL 未提取时，规则静默失配 | P0 |
| LLM 输出校验不足 | `_call_llm()` 只校验 `semantic` 为 dict、`rv_trace` 为 list；没有严格枚举 scenario、标签、实体类型和规则引用 | LLM 轻微格式/命名漂移会直接降低命中率，随后回退到宽泛审批 | P1 |
| 工具映射不足 | `_validate_tool_name()` 只识别少量精确工具名；未知工具如 `before_prompt_build` 不会转成规范权限族 | Hook 工具名称无法映射为可判断的操作 | P0 |
| 阈值不可校准 | `_confidence_for()` 由固定启发式从 0.6 起步；ConstraintEngine 低于阈值直接丢弃结果；没有按场景/风险等级校准 | 低置信度“未参与判定”与“安全”无法区分；阈值变化没有 ROC/PR 依据 | P0 |
| 评分不能表示部分匹配 | `_match_score()` 只有所有声明约束都满足才返回分数，满足后通常归一化为 1.0；管线只取排序后的第一条规则 | 分数不是匹配可信度；多个规则同分时可能不能优先选择最高风险证据 | P1 |
| 兜底过于宽泛 | 敏感 action 未命中时统一 `ask`；没有低风险自动放行策略、澄清请求和规则缺口队列 | 人工审批量随新工具/新措辞线性增长 | P0 |
| 审批边界不清 | OpenClaw 是最终审批中心，但本项目本地判定、白名单和 Hook 结果没有统一的 `coverage`/`evidence` 交接字段 | 审核员看到“待确认”，看不到是风险、未知还是缺字段 | P1 |

### 12.3 规则库迭代方案

采用“安全规则 + 正向许可模板 + 场景 Trace”三层，而不是继续扩展单一黑名单：

1. **安全规则层**：保留 `CMD/FILE/NET/CFG/SKL/API` 高风险规则，统一为 PMKB policy record，增加 `rule_version`、`match_mode`、`required_fields`、`negative_conditions`、`scope` 和 `test_vectors`。
2. **正向许可层**：为 P0 场景建立低风险允许模板，例如 workspace 内只读、内部域查询、已批准收件人发送、固定命令 AST。模板必须限定主体、资源、作用域、目的和 TTL，不能变成全局白名单。
3. **业务 Trace 层**：为 EX-10 群发、EX-19 数据库导出、EX-27 批量文件操作及 AT-01～AT-08 建立“任务目的 → 必要权限序列 → 允许范围 → 禁止组合”的可执行样本。

规则入库流程：

```text
人工/审计样本 → 脱敏归一化 → 权限族与资源作用域标注
  → 正例/反例/边界例 → 离线评估 → 版本化发布 → 有限样本试运行 → 晋级
```

规则缺口必须产生 `gap_id` 和待补样本，而不是直接新增一条关键词。规则合并、重复、冲突和长期未命中应由 CI 检查；OPA 的策略测试实践也把“通过/失败/错误”和策略覆盖率作为独立结果，项目可借鉴同样的覆盖门禁（见 [OPA Policy Testing](https://www.openpolicyagent.org/docs/policy-testing)）。

### 12.4 输入特征工程升级

将当前标签集合升级为规范化特征对象，至少包含：

```text
action_family / tool_id / argument_ast
resource_type / resource_id / scope / quantity
principal / agent / capability_lineage / goal_id / session_id
source_provenance / trust / recipient_zone / data_classification
purpose / time_range / exclusions / negations
side_effect / irreversibility / reversibility
```

特征工程分四步：

1. **工具规范化**：维护 `tool_id → operation_family` 映射；未知工具先映射为 `unknown_tool`，再依据参数和 manifest 推断，不允许因名称未知就丢弃操作语义。
2. **参数 AST**：命令使用安全解析器提取动词、路径、管道、重定向和网络目标；URL、邮箱、路径、SQL/查询条件分别规范化，避免只依赖原始文本子串。
3. **中文语义与否定**：保留 `negated`、`excluded_entities`、`scope_limit` 和 `recipient_policy`；“不要外发”不能只触发 `外发` 标签而丢掉否定。
4. **多源一致性**：用户指令、Hook 参数、工具 manifest、历史授权和模型输出分别记录 provenance；冲突时以可信参数和系统策略优先，模型只提供候选。

### 12.5 匹配算法调优与重构

短期保留现有规则路径，增加候选召回和可解释评分；中期将确定性谓词与语义召回分层：

```text
候选召回：精确 action/resource 索引 + 同义词 + 可选 embedding
确定性匹配：scope/negation/entity/argument AST/temporal predicates
关系推理：permission closure + toxic combination + least privilege
结果校准：match confidence 与 security risk 分离
```

建议匹配置信度 `M`：

```text
M = 0.40 * action_semantic
  + 0.25 * entity_completeness
  + 0.20 * rule_specificity
  + 0.15 * provenance_agreement
```

各项取 0～1，并在标注集上做温度校准或 isotonic calibration；`M` 只表示“理解/覆盖得有多确定”，不表示“风险有多高”。

规则匹配结果不得只返回一条 `(rule, score)`，而应返回：

```json
{
  "match_status": "matched|partial|unknown",
  "candidates": [{"rule_id": "...", "score": 0.91, "missing": []}],
  "selected_rule_ids": ["..."],
  "coverage": "complete|partial|unknown",
  "missing_features": ["resource.scope"],
  "conflicts": [],
  "calibrated_confidence": 0.91
}
```

### 12.6 兜底机制与人工审批降载

兜底不再是“未命中即人工确认”，而是四级路由：

| 路由 | 适用条件 | 行为 |
|---|---|---|
| `auto_allow_audit` | coverage 完整、低风险、主体/目的/作用域在许可模板内 | 自动放行，写审计和规则版本 |
| `clarify_then_retry` | 低/中风险，仅缺 1～2 个可补字段 | 生成结构化澄清问题，补齐后重新匹配 |
| `openclaw_approval` | 高影响、规则冲突、权限扩张或组合风险 | 只在 OpenClaw 审批中心生成一条申请，附 evidence |
| `fail_closed` | 命中硬阻断、身份不可信、规则完整性异常 | 立即阻断并生成审计报告 |

自动放行模板采用“主体 + 目的 + 权限 + 资源范围 + TTL + 负向约束”绑定，不能直接复用现有命令前缀白名单。OpenClaw 仍是唯一审批入口，本项目只提供风险分类、证据和状态同步。

### 12.7 量化目标与观测口径

基础 PMKB 规则直接参与运行时决策。对于新规则、批量发布或需要扩大自动放行范围的版本，先执行离线规则/攻击向量回放，再使用最多 20 条相关事件进行有限样本校验；个人模式可改用事件计数或显式确认，不要求长期保留记录。以下目标是建议值，不能冒充当前已达到的结果：

| 指标 | 定义 | 灰度目标 |
|---|---|---|
| 规则匹配成功率 | `coverage=complete` 且命中确定性规则的事件 / 可评估事件 | P0 场景 ≥ 85%，较基线提升 ≥ 25 个百分点 |
| 低风险自动放行率 | 低风险标注集中 `auto_allow_audit` / 低风险事件 | ≥ 70% |
| 人工审批下降率 | `1 - 新 pending_approval / 基线 pending_approval` | 总量下降 ≥ 40%；低风险子集下降 ≥ 60% |
| 高风险召回率 | 攻击/关键风险样本被 `block` 或 `openclaw_approval` 的比例 | ≥ 98%；硬阻断集关键漏报为 0 |
| 自动放行精确率 | 自动放行中经人工/离线 oracle 判定为安全的比例 | ≥ 99% |
| 未知率 | `match_status=unknown` / 可评估事件 | P0 场景 ≤ 10% |
| 置信度校准 | ECE 或 Brier score，按风险层分别统计 | ECE ≤ 0.05 |
| 本地匹配延迟 | 不含 LLM 的 p95 | ≤ 50 ms |
| 澄清转化率 | 澄清后一次重试完成匹配的比例 | ≥ 70% |

任何人工量下降都必须同时满足高风险召回率和自动放行精确率门槛；不能通过简单降低阈值或放宽白名单“制造”效率指标。

## 13. 权限组合风险“博弈”模型设计

这里的“博弈模型”采用**约束型 Stackelberg 决策模型**实现，而不是让模型自由学习审批策略：申请主体先提交权限增量，Guard 作为安全领导者计算硬约束、最小权限和风险，OpenClaw 审批中心保留最终人工决策权。这样既表达申请方的任务效用，也不允许申请方通过自报风险或调低阈值获利。

### 13.1 模型主体与状态

核心本体为 `principal`，而不是工具名称：

```text
Principal = human | agent | skill | service
PrincipalState = {
  principal_id, agent_id, roles, active_capabilities,
  capability_lineage, trust_level, revocations, risk_history
}
```

一次决策状态为：

```text
S = (principal, goal, scenario, session,
     P_current, P_requested, Trace_required, Context, Evidence)
```

其中 `goal_id` 用于跨 session 任务分区；安全合并仍必须校验 principal、agent 和 capability lineage。

### 13.2 输入参数

```json
{
  "request_id": "req-...",
  "principal": {"id": "agent-7", "type": "agent", "trust": 0.95},
  "goal": {"goal_id": "quarterly-report", "purpose": "report_send", "confidence": 0.91},
  "session": {"session_id": "s-2", "source": "openclaw_hook"},
  "current_permissions": ["data.read:workspace"],
  "requested_permissions": ["data.export:external"],
  "required_trace": ["data.read:workspace", "report.generate", "message.send:approved_domain"],
  "operation": {"tool_id": "mail-send", "family": "message.send", "arguments": {}},
  "resource": {"type": "report", "scope": "workspace", "classification": "internal"},
  "context": {"recipient_zone": "external", "time": "...", "approval_state": "none"},
  "provenance": {"user": "...", "tool_manifest": "...", "semantic_confidence": 0.91}
}
```

### 13.3 输出参数

```json
{
  "decision": "allow|clarify|openclaw_approval|block|partial_grant",
  "risk_score": 0,
  "match_confidence": 0.0,
  "effective_permissions": [],
  "requested_delta": [],
  "combo_violations": [],
  "least_privilege": {
    "required": [], "excessive": [], "redundant": [], "scope_expansion": []
  },
  "rule_evidence": [],
  "missing_fields": [],
  "approval_payload": {"owner": "openclaw", "dedupe_key": "..."},
  "audit_record": {"policy_version": "...", "replay_hash": "..."}
}
```

### 13.4 双重校验逻辑

第一重是**知识库安全组合校验**：

```text
P_effective = closure(P_current)
P_after = closure(P_current ∪ P_requested)
if P_after ∩ forbidden_permissions ≠ ∅:
    hard_block
if toxic_with(P_after, principal, goal, window) matches:
    block_or_openclaw_approval
if conflicts(P_after) or SoD violation:
    openclaw_approval
```

第二重是**业务最小必要 Trace 校验**：

```text
P_required = closure(permissions(Trace_required, goal, scenario))
Δ = P_after − P_effective
excessive = Δ − P_required
redundant = P_requested ∩ P_effective
scope_expansion = scope(P_after) - scope(P_required)
```

若 `excessive` 或 `scope_expansion` 非空，申请不应自动放行；低影响且可由主体补充目的的请求进入 `clarify`，高影响请求进入 OpenClaw 审批或阻断。

### 13.5 风险评分规则

硬约束优先于分数。非硬阻断情况下，使用 0～100 的可解释分数：

```text
R_combo = 100       # 命中 forbidden/conflict/approval_bypass
          80         # 命中 toxic combination
          0          # 未命中组合

R_least = 100 * |excessive| / max(|Δ|, 1)
          + 20 * scope_expansion_flag
R_critical = max(permission_criticality in P_after)  # 0/25/50/75/100
R_uncertain = 20 * missing_required_fields
              + 20 * untrusted_provenance

R = max(R_combo, min(100,
      0.45 * R_least + 0.25 * R_critical
    + 0.20 * R_uncertain + 0.10 * R_context))
```

初始 `R_context` 可由外部域、不可逆性、批量规模和时间异常组成；权重必须用标注样本校准，并在规则版本中固定。`match_confidence` 和 `R` 不能互相替代：高置信度地识别出危险组合仍应阻断，低置信度地识别低风险动作则应澄清。

建议决策带：

| 条件 | 决策 |
|---|---|
| 命中硬阻断、身份不可信或 `R_combo=100` | `block` |
| `R ≥ 70` 或存在高影响 excessive/scope expansion | `openclaw_approval` 或 `block` |
| `35 ≤ R < 70` 或 `match_confidence < 0.75` | `clarify`；无法补齐则 OpenClaw 审批 |
| `R < 35`、coverage 完整、在 required Trace 内 | `allow` 或 `partial_grant` |
| 请求权限完全已存在 | `partial_grant`/记录 redundant，不重新扩大授权 |

### 13.6 博弈决策逻辑

申请主体的可选动作是提交、补充目的、减少权限或取消；Guard 的响应是 `allow`、`partial_grant`、`clarify`、`approval`、`block`。任务效用可写为：

```text
U(action) = task_utility(action)
           − latency_cost(action)
           − risk_penalty(action)
```

但 `forbidden`、SoD、硬危险组合和超出必要 Trace 的高影响权限是不可违反约束；只有在可行集合内最大化 `U`。`partial_grant` 优先返回任务所需最小权限，避免“全量批准或全量拒绝”造成审核堆积。

### 13.7 与现有审批流程集成

在现有流水线

```text
annotate → detect → constraint → RV → session → controller
```

中增加：

```text
annotate → permission_normalize → permission_combination_check
         → detect/constraint → RV → session → controller
```

集成约束：

1. `permission_combination_check` 只生成一份 `permission_decision` 和 evidence，不新建第二审批中心。
2. `block` 直接由 Guard 阻断；`allow/partial_grant` 继续现有自动执行；`clarify/openclaw_approval` 统一转换为一个 OpenClaw checkpoint 申请。
3. 审批 payload 必须携带 `request_id + principal_id + goal_id + policy_version + requested_delta + combo_violations + least_privilege.excessive`，便于去重和及时同步。
4. OpenClaw 审批结果回写同一 `request_id`，Guard 只更新状态和审计，不再创建本地镜像审批。
5. 任何模型异常、知识库版本不一致、身份无法确认，进入 `fail_closed` 或针对性 `clarify`，不得回退为无证据的永久人工队列。

## 14. 模型测试与验证方案

### 14.1 测试数据分层

建立四个互斥集合，避免只测攻击样本：

| 集合 | 内容 | 目的 |
|---|---|---|
| `R+` | 已知安全规则和低风险正向许可模板 | 测自动放行精确率 |
| `R-` | 47 条检测规则、硬阻断和历史攻击样本 | 测安全召回率 |
| `B` | 边界样本：否定、范围、批量、外部域、重复授权、缺字段 | 测校准与澄清 |
| `U` | 新工具、未知措辞、未知参数和未入库场景 | 测缺口发现与兜底 |

每一条样本包含自然语言、原始 Hook payload、规范化 Trace、主体/当前权限、期望决策、规则证据和数据来源。用户真实样本脱敏后按场景和风险分层，不能把随机切分当作独立测试集。

### 14.2 必测风险矩阵

覆盖现有办公场景 EX-10/EX-19/EX-27、AT-01～AT-08，以及：

1. 当前已有权限与新权限完全重复；
2. 同一权限扩大 workspace → outside/external/bulk；
3. `secret.read + network.egress`、`credential.read + process.execute`；
4. `config.modify + audit.disable`、`approval.bypass + high-impact`；
5. 主体 A 与主体 B 共享 `goal_id` 但 lineage 不同；
6. session A 读取、session B 外发，包含重启和事件重复；
7. skill manifest 声明只读、运行时请求写入/网络/安装；
8. 中文否定、同义改写、混合中英文、参数与自然语言冲突；
9. 缺少路径、收件人、URL、主体或目的字段；
10. 规则版本回滚、撤销、TTL 过期和知识库损坏。

### 14.3 评估方法

- **规则匹配**：按场景、风险层、工具族计算 precision/recall/F1、coverage、unknown rate；输出混淆矩阵。
- **特征消融**：分别关闭实体、scope、provenance、argument AST、goal lineage，量化每类特征对召回和误报的贡献。
- **阈值校准**：在训练/校准/测试三份数据上确定 `M` 和 `R` 的阈值，不用测试集反复调参。
- **攻击回放**：对 AT-01～AT-08 做顺序扰动、语义改写、跨 session、快照恢复和重复事件回放。
- **审批负载**：按事件去重后的 `request_id` 计算人工申请数、平均处理时延、澄清次数和一次通过率。
- **性能**：测本地匹配 p50/p95/p99、知识库加载、闭包计算和持久化恢复；LLM 仅作为异步候选，不计入安全热路径基线。

### 14.4 安全验收门槛

1. 硬阻断集关键风险召回率 100%，不得以降低人工量换取漏报；
2. 自动放行精确率 ≥ 99%，任何误放行必须阻断发布；
3. P0 场景规则匹配率较基线提升 ≥ 25 个百分点，未知率 ≤ 10%；
4. 总人工审批量下降 ≥ 40%，低风险人工审批下降 ≥ 60%；
5. 不同主体共享 `goal_id` 的错误合并率 0；
6. snapshot/replay 前后决策、规则版本和审计哈希一致；
7. 关键规则、权限组合和最小权限 Trace 覆盖率 100%；
8. 文档、规则 schema、攻击夹具、全量测试和性能基线全部通过后才允许有限样本试运行。

### 14.5 观测与持续迭代

每次决策记录 `match_status`、`unknown_reason`、`candidate_rule_ids`、`selected_rule_ids`、`match_confidence`、`risk_score`、`human_override`、`final_outcome` 和 `policy_version`。每周生成规则缺口报告：

```text
unknown_reason → 缺失字段/错误映射/规则覆盖不足/冲突/模型失败
                 → 样本聚类 → 人工确认 → 新规则或特征变更
```

规则变更必须经过离线回归、攻击集、合法集和有限样本试运行；不允许直接从人工审批日志自动学习为 allow 规则。NIST ABAC 指南强调授权依赖主体、客体、操作和环境属性，[NIST SP 800-53 AC-5/AC-6](https://csrc.nist.gov/CSRC/media/Projects/risk-management/800-53%20Downloads/800-53r5/SP_800-53_v5_1-derived-OSCAL.pdf) 则分别要求职责分离与最小权限；本项目的输入契约、双重校验和审计字段正是将这两个原则落到运行时。

## 15. 推荐实施顺序

1. **基础规则先生效、再测量调优**：上线 `match_status/unknown_reason/coverage` 指标；个人模式立即执行基础 PMKB，使用显式确认或最多 20 条相关事件的小样本证据调整用户偏好。
2. **先解决规则双轨和未知工具**：统一 PMKB ID、工具映射、正向许可模板和 Hook evidence；这一步即可减少一批无谓审批。
3. **再做特征与匹配重构**：引入参数 AST、否定/范围、候选召回、校准置信度和澄清路由。
4. **随后接入权限组合模型**：先单 session 验证闭包、危险组合和最小 Trace，再接 `goal_id` 跨 session。
5. **最后扩大自动放行**：只有当自动放行精确率、高风险召回率和审计完整性同时达标，才扩大许可模板。

该顺序能直接回应当前人工负载问题，同时避免通过盲目放宽规则制造新的权限组合风险。
