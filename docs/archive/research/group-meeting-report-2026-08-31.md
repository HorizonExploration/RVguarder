# 组会汇报：权限建模与知识库落地 + OpenClaw 审批交接优化（AgentDojo 待重跑）

> 汇报日期：2026-08-31 | 承接上次汇报（2026-08-14，RV 阶段 A–F 落地）
> 仓库 HEAD：`8a51f38`（2026-08-30，已推送 origin/master）
> 工作区另有 49 个文件未提交（8-30 审批交接修复 + AgentDojo 评测增量）
> 状态：草稿，供组会汇报使用；AgentDojo 首轮实验判定无效，指标不可采信
> **状态更新（2026-09-02）：** 本文是 8 月 31 日快照；其中 HEAD、未提交文件数量、PMKB 计数、DetectionEngine 及待办事项均保留当时语境，不是当前事实。版本元数据、FastAPI 单入口和生产 DetectionEngine 退役事项已在后续工程统一中完成；当前结论见[工程统一报告](../architecture/v070-engineering-unification-report-2026-09-02.md)。

---

## 〇、汇报概览

上次汇报结束时，系统能"判定动作安不安全"；这次我们把**"凭什么安全"变成了可建模、可追溯、可验证的权限体系**：

1. **权限建模（核心）** —— 用 RBAC+ABAC+ReBAC+Capability 混合模型回答"谁、对什么、能做什么、为什么"；Authorization Trace 九维本体 + 四状态证据匹配 + 最小权限闭包/差分 + 危险组合风险图 + 权限自动机 + 主体级跨 session RV；
2. **PMKB 权限知识库（载体）** —— 27 operations / 31 规则 + 47 LEGACY / 29 traces / 9 relations，案例来自 Okta / MS / Solorigate 等真实事件；legacy 47/47 全量迁移；
3. **OpenClaw 审批交接优化** —— 修复"长命令必被拦、安全读取被误拦"三类链路问题；
4. **AgentDojo 升级评测** —— 框架完成，**demo 首轮无效，指标不可采信，待重跑**。

一句话：**从"规则判定"走向"权限建模"——每个决策都有可追溯的 Authorization Trace、可验证的最小权限、可预警的危险组合；评测基础设施就绪但首轮数据作废。**

---

## 一、权限建模（核心）

### 1.0 起点问题：单步标签匹配的四个根本缺陷

旧 DetectionEngine 是"工具名 + 语义标签 → 规则命中"，对照文献和自建攻击矩阵，存在四个硬缺口：

| 缺陷 | 表现 | 对应攻击矩阵 |
|---|---|---|
| 无权限本体 | 工具名被直接当权限，"工具叫什么"代替"该不该做" | AT-07 工具名伪装 |
| 无组合风险 | 单步都安全，串起来出事 | AT-04 toxic combination |
| 无最小权限 | 不知道 Agent 已持有什么、多申请了什么 | AT-02 过度权限、AT-03 权限膨胀 |
| 无跨会话视角 | session 独立窗口，换 session 就漏 | AT-05 跨 session 数据流 |

这四点是设计动机的总纲：**建模补本体，风险图补组合，闭包差分补最小权限，principal RV 补跨会话。**

### 1.1 权限本体：为什么是"混合模型"，而不是择一

**文献问题**：NIST SP 800-162（ABAC）强调主体/客体/环境属性与动态细粒度；NIST RBAC 提供角色层级、SSD/DSD 职责分离；Google Zanzibar（USENIX ATC 2019）把授权建模为主体—资源**关系图**并强调一致性与因果顺序——但没有一个模型单独覆盖 Agent 场景（Agent 既是主体又会被 Skill 委派）。

**设计选择**：四个模型各取一段，对应不同稳定度：

```text
RBAC       稳定职责模板        Agent/skill/用户的角色基线
ABAC       动态环境属性        时间、敏感度、工作区、收件人域、审批状态
ReBAC      关系图             主体—Agent—session—tool—resource—owner
Capability 短期授权+委派       一次性授权及其 lineage
```

**实现**：工具调用不直接等于权限——`TraceCompiler` 先做规范化：工具名/别名 → canonical 权限族（`file.read / process.execute / network.egress / secret.read / session.token.read ...`），再叠加资源作用域、数据敏感度和主体身份。

**作用**：AT-07 的"工具名普通但参数在删除/外发"不再漏——参数副作用归一化为真实权限族后判定。

### 1.2 Authorization Trace：九维权限本体

**文献问题**：AgentSpec（ICSE 2026）的 `trigger → predicate → enforcement` 是好的运行时结构，但无法回答审计问题："这条规则命中了，证据够不够？"；Zanzibar 的关系图思想正确，但本项目不能部署分布式授权服务。

**设计选择**：把 Hook 事件归一化为九维 Authorization Trace，覆盖度显式建模：

| 维度 | 字段 | 安全含义 |
|---|---|---|
| 主体 | `principal.id/type/trust` | 人/Agent/Skill/Service；**只有可信身份可参与跨 session 合并** |
| 执行体 | `agent_id` + `capability_lineage` | 区分同一用户下不同 Agent 和能力来源，防错误继承 |
| 操作 | `operation.family/tool_id/aliases` | 目录解析；解析不了就是 `unknown_tool` |
| 资源 | `resource.type/ids` | 路径、URL、收件人、文档、表 |
| 范围 | `resource.scope` | workspace/managed_project/outside/external/unknown；**unknown 不当宽泛许可** |
| 数据 | `data.classification/quantity` | public/internal/sensitive/secret |
| 上下文 | `recipient_zone/purpose` | 内部/外部目的地、业务目的 |
| 覆盖度 | `coverage.status/gaps/conflicts` | complete/partial/unknown/conflict |
| 来源 | `provenance/trust/confidence` | 语义从哪来；**不可信文本不直接变授权** |

**实现**：`PolicyBundle.load → TraceCompiler`，与语义层 `entities/labels/classification` + 历史 `rv_trace` 合并；缺字段时状态降级为 partial/unknown 并升级处置。

**作用**：解决"命中规则但无法证明覆盖"的审计问题——每次决策都能回答"证据从哪来、缺了什么、可不可信"。

### 1.3 匹配即解释：四状态 + 加权评分

**文献问题**：OPA/Rego 与 AWS Cedar（PARC/PARX 授权请求）共同表明——**在线策略系统的稳定性来自规范化请求对象和显式 schema，而不是"理解得像不像"**；NL→policy 研究（Synthesizing Access Control Policies using LLMs、Prose2Policy、AGentVLM）也一致指出：语法正确 ≠ 语义正确，必须经结构化中间表示、验证和正反例。

**设计选择**：规则命中 = 证据比对，不是关键词交集：

- 候选规则四状态：`matched` / `partial`（缺字段）/ `unknown`（映射不可确认）/ `conflict`；
- 匹配分数是**解释性证据**而非放行开关：
  `0.40×操作动作 + 0.25×必填字段完整度 + 0.20×谓词特异性 + 0.15×来源可信度`；
- **任何 unknown/conflict 都阻止 `auto_allow_audit`**；无法映射的工具带缺口进审批。

**实现**：`PolicyEvaluator` 对规则 required fields / positive predicates / negative conditions 逐项比对，缺口合并进规则证据，生成候选规则 + `match_status`。

**作用**：AT-06（语义改写/否定/范围："仅发内部域""除 X 外"）不再因关键词丢失而误放行——否定条件、例外、作用域作为结构化谓词保留。

### 1.4 最小权限：闭包 + 差分

**文献问题**：Saltzer & Schroeder（1975）的最小权限原则、NIST SP 800-53 AC-6、CISA IAM 最佳实践，都把"最小权限 + 权限清单 + 定期复核"放在同一治理闭环——但传统系统是静态配置，Agent 的权限是**运行时动态累积**的。

**设计选择**：把最小权限做成**运行时差分**，而不是静态审查：

- `PermissionClosure`：计算"已持有权限"的传递闭包（含角色/能力蕴含）；
- `PermissionDiff`：对比**已持有 vs 新增请求**——重复授权标记 redundant 不增加 grant；scope 扩张（workspace → outside）触发审批；
- 委托/委派必须带证据，无证据的提权请求被拒。

**实现**：Hook 事件携带 `current_permissions / requested_permissions / required_trace`，进入 `permission_diff.py`。

**作用**：AT-02（只要摘要却带全量能力）→ 请求只获得 read；AT-03（重复申请 + scope 扩张）→ redundant 不增权、outside 触发审批。

### 1.5 危险组合：RiskGraph

**文献问题**：NIST SP 800-53 AC-5 职责分离（SoD）要求"单个主体不得同时具备冲突能力"；真实攻击案例（EchoLeak CVE-2025-32711、Unit 42 Agent Session Smuggling、MELON/InjecAgent 的注入链）都是**单步安全、组合致命**——单事件规则无法表达。

**设计选择**：超边（hyperedge）式危险组合，命中即升级/阻断：

| 组合 | 处置 |
|---|---|
| `credential.read + network.egress + external_target` | **block** |
| `session.token.read + network.egress + external_target` | **block** |
| `identity.permission.grant + data.export + external_recipient + sensitive_data` | **block** |
| `identity.auth.modify + audit.modify` | 审批 |

**实现**：`relations/p0-combinations.json` 声明 `toxic_with / conflicts / implies` 关系；`RiskGraph` 在请求时做组合闭包查询。实现上采用**稀疏权限集合 + 蕴含闭包 + 组合超边索引**，避免 `Q=2^P` 的状态爆炸（形式化说明不等于工程数据结构）。

**作用**：AT-04（`credential.read → process.execute` 或 `config.modify → audit.disable`）命中超边升级/阻断；EchoLeak 类的"读凭据→外发"链被前置拦截。

### 1.6 权限自动机 + 主体级跨 session RV

**文献问题**：Schneider / Basin 的 Enforceable Security Policies 给出"策略可执行性"的形式化边界；QEA（Quantified Event Automata）用参数化切片支持 per-binding 独立监视；AgentDojo / InjecAgent 证明单会话防护可被"换 session 继续攻击"绕过。

**设计选择**：两层 RV 叠加：

- **session-local**：现有行为 DSL + 滑动窗口（2026-08-14 已落地）；
- **principal-global**：权限自动机按主体编译，键 `(principal_id, agent_id, capability_lineage)`，`runtime/rv-state.json` 持久化 + TTL，重启可恢复；审批通过的动作成为主体**有效能力**，跨 session 组合评估，效果只升不降。

**实现**：`PermissionAutomatonCompiler` 把 PMKB 规则编译为权限监视器接入 RV 引擎——权限策略与运行时验证共用同一份声明式来源，无两套真相。

**作用**：AT-05（session A 读 secret、session B 用同一 capability 外发）不再漏报——按可信 principal 聚合，命中组合即处置。身份不可信时隔离或升级，绝不静默继承。

### 1.7 攻击矩阵对照（落地验证）

| 攻击 | 改造前 | 改造后 |
|---|---|---|
| AT-01 间接注入→外发 | 部分覆盖（escalate） | 来源可信度+secret+egress 组合 block |
| AT-02 过度权限 | 无最小权限比较 | 闭包+差分，只授 read |
| AT-03 权限膨胀/扩张 | 无法区分 | redundant/outside 分别处置 |
| AT-04 toxic combination | 单步漏 | 超边命中升级/阻断 |
| AT-05 跨 session | 独立窗口漏报 | principal 聚合命中 |
| AT-06 否定/例外/范围 | 关键词丢失 | 结构化谓词保留 |
| AT-07 工具名伪装 | 只看名字漏 | 参数副作用归一化 |
| AT-08 供应链 skill | 无 manifest 比对 | 能力声明 vs 运行时差分 |

---

## 二、PMKB 权限知识库（载体）

### 2.1 为什么还要一个"知识库"

权限模型是**逻辑**，还需要一个**可版本化、可校验、可回归**的物理载体——否则规则散落在代码里，无法回答"这版策略改了什么、和上版是否一致"。

**文献问题**：OPA 的策略版本化 + 决策日志、Cedar 的 schema 校验，共同经验是"策略要像代码一样管理"；本项目还要求单机可启动、低延迟、无侵入，所以**首期不引入 OPA/Cedar 作为在线强依赖，只吸收其模型与验证思想**（融合方案里明确的选择）。

### 2.2 目录结构

| 文件 | 数量 | 对应建模需求 |
|---|---|---|
| `schema/permissions.schema.json` | 1 | 约束 bundle 结构（Cedar 式 schema 校验） |
| `operation-catalog.json` | 27 operations | 工具名/别名 → canonical 权限族（1.1 规范化） |
| `rules/p0-office.json` | 31 rules（22 条 P1-*） | 单步规则：匹配条件+处置+来源+正反例 |
| 运行时兼容规则 | 47 `LEGACY-*` | 由 47 条 DetectionRule 自动生成，同时进 ConstraintEngine/PMKB/监视器 |
| `traces/p0-office.json` | 29 traces | 每条规则的最小必要权限范围+正反例（1.4 的验证素材） |
| `relations/p0-combinations.json` | 9 relations | toxic_with/conflicts/implies（1.5 超边数据） |
| `tests/p0-vectors.json` | 29 vectors | 固定输入、预期效果、回归类别 |

每个规则记录至少含：`id / version / effect / priority / match / required_fields / negative_conditions / source / test_vectors / rollback_state / positive_examples / negative_examples`。

### 2.3 工程保障（怎么实现"可信"）

- **加载即校验**：拒绝重复 ID、未知 operation、版本不一致、缺必填字段；
- **递归冻结**：加载后记录不可变，防运行时篡改；
- **双目录 parity**：源码 `policies/permissions/` 与打包 `openclaw_guard/policy/data/permissions/` 同版本同内容，测试断言；
- **确定性索引**：向量检索只做候选召回，授权决定由确定性 schema + 评估器确认（修正"embedding 当授权依据"的方案错误）。

### 2.4 基线处置（权限族视角）

| 权限族 | 基线效果 |
|---|---|
| `directory.read` / `table.read`（工作区内、证据完整、低敏感） | `auto_allow_audit` |
| `document.write` / `file.write` / `data.export` / `network.egress` / `process.execute` / `secret.read` | 审批（敏感导出 block） |
| `session.token.read` | **block** |
| `identity.permission.grant` / `identity.auth.modify` / `audit.modify` | 审批 |

缺 principal/resource/scope/recipient → partial/unknown → 处置升级，不静默放行。

### 2.5 网络案例基线（规则从哪来）

| 案例 | 提炼的权限族/规则 |
|---|---|
| Okta Support 事件（服务账号凭据暴露、HAR 令牌泄露） | `session.token.read` block、`credential.read` 审批 |
| MS Token Tactics（Pass-the-Cookie、MFA/设备变更） | `identity.auth.modify` 审批、token+egress 组合 |
| MS Solorigate（OAuth 应用/服务主体权限被增） | `identity.permission.grant` 审批、grant+export+external+sensitive 组合 |
| Google / CISA（IAM 治理闭环） | 最小权限差分、SoD 组合 |
| EchoLeak CVE-2025-32711 / Agent Session Smuggling | 组合超边、跨 session 聚合 |

附带修复：`read`/`cat`/`grep`/`ls` 不再因带路径被误判为 `file_write`（消除误升权）。

### 2.6 legacy 迁移

47 条旧检测规则 → 动态生成 `LEGACY-<id>` 兼容记录，**47/47 双判定对齐**（ConstraintEngine + PMKB 一致）；DetectionEngine 保留为快速单步防线，退役闭环待做。

---

## 三、确定性安全增强（8-29 增量）

- **确定性命令分类**：read_only/mutating/destructive/network/privileged/unknown，决策不依赖 LLM；管道仅全只读才通过；
- **scope 五分类落地**：受管项目低风险读取豁免完整身份校验；
- **会话风险衰减**：300s 衰减，low/routine/safe 不计入攻击链分数；
- 中文审批说明，文档同步。

---

## 四、OpenClaw 审批交接与误拦截优化（8-30，未提交）

### 4.1 根因：三类链路问题，不是"规则太严"

1. **原生工具未建模**：`memory_search`、`sessions_history` 等控制面读取被当普通调用 → 缺 scope 进审批；
2. **session 升权过冲**：critical 后把安全 `allow/read` 也改写为 `revise`；
3. **审批说明超长**：长命令说明塞进审批请求用户字段 → schema 报错（实测 5 次失败）。

### 4.2 修复

| 修复 | 内容 |
|---|---|
| 原生工具显式建模 | `sessions_*`→`session.read`、`memory_*`→`memory.read`、`agents_list`/`get_goal`→只读族；PMKB 自动放行+审计；`sessions_send`/`sessions_spawn` 不继承只读信任 |
| 参数安全检查 | 外部 URL/绝对路径/跨 session 目标 → 退出低风险信任 |
| 升权只作用于危险调用 | `block` 保持；安全 `allow/read` 不被历史 critical 改写 |
| 审批字段边界 | 标题 ≤80、说明 ≤240 字符；完整规则/Trace 留审计 |
| 生命周期收拢 | `before_prompt_build` 只审计；`onResolution` 唯一决策源；>6 分钟无回调 → `approval_timeout`；清理临时插件路径 |

### 4.3 验证

- 定向回归：**192 passed / 4 subtests，42.57s**；改造前全量基线：**513 passed / 18 skipped**；
- 离线 smoke replay：3 个原生只读调用 100% `allow`；
- 边界未变：高危写入/外联/凭据读取/跨代理发送/未知命令不因优化放行。

---

## 五、AgentDojo 升级评测 —— ⚠️ 首轮无效，待重跑

### 5.1 已完成（基础设施，可信）

- 官方 `get_suite()` / `load_attack()` / TaskSuite 评分链路；三组对照 noguard/legacy/candidate；
- 审批语义分离 `deny` vs `allow-once`，不把弹审批误计成阻止；
- 环境就绪：agentdojo 0.1.35 + Python 3.11.15，preflight 通过。

### 5.2 ❌ 首轮判定：无效

demo 首轮（v1.2.2, MiniMax-M2.7-highspeed, 168 episodes）**全部不可采信**：

1. **`max_tool_iters = 2` 截断**：demo 硬编码每集最多 2 次工具调用，实际 1~4 次、平均 6~8 秒——任务正常需 10~30+ 步，攻击链根本没机会形成；
2. **noguard 基线攻击成功率 0%**：无防护对照攻击成功率为 0 → **攻击注入链路未生效**（论文级无防护成功率通常 20~80%）；三组全 0% → "100% 预防率"是假象；
3. **历史污点**：candidate 先前因缺 `OPENCLAW_GUARD_HOOK_TOKEN` 401，重跑后才出数。

**报告中的预防率 100%、审批负载 54→52、p95 等数字全部作废，不得用于结论。**

### 5.3 重跑前置条件

- `max_tool_iters` 提到 **10~30**；
- **先验证 noguard 攻击基线非 0**，再跑 legacy vs candidate 对比；
- 核对 utility 与攻击链完整性（不能只看安全指标）。

---

## 六、当前边界

- 版本元数据仍 `0.3.0`，与文档产品版本 `v0.7.0-dev` 不一致；
- 默认 HTTP 入口仍是 `legacy_web.py`，FastAPI 双轨待收敛；
- DetectionEngine 未退役；ptrace/eBPF collectors 仍是探测桩；基线 DFA 默认不加载；
- **-40% 人工审批目标是路线图目标，尚无真实流量实测**；
- 工作区 49 个文件未提交。

---

## 七、下一步计划

| 优先级 | 事项 |
|---|---|
| P0 | **重跑 AgentDojo**：修 `max_tool_iters` + 验证 noguard 攻击基线 → 三组对照 |
| P0 | 提交 8-30 未提交增量（标注首轮实验无效） |
| P0 | 重启 gateway → 采集真实任务 before/after 指标 |
| P1 | 统一版本元数据；默认入口切 FastAPI |
| P2 | DetectionEngine 退役闭环；软著 + 答辩材料 |

---

## 附：汇报口径速查

- **30 秒版**：把"规则判定"升级为"权限建模"——混合模型（RBAC/ABAC/ReBAC/Capability）+ 九维 Authorization Trace + 最小权限差分 + 危险组合风险图 + 跨会话主体验证，吸收 NIST/Zanzibar/OPA/AgentSpec 的思想但保持单机无侵入；AgentDojo 框架就绪，首轮数据作废待重跑。
- **3 分钟版**：讲 1.0（四个缺陷）→ 1.1/1.2（混合模型 + Trace）→ 1.4/1.5（最小权限 + RiskGraph）→ 1.7 攻击矩阵对照 → 五.2（为什么无效）。
- **10 分钟版**：按正文过；文献引用点放在每节第一句，攻击矩阵对照表适合投屏讲。
