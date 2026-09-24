# PMKB 定位、推理能力与链路问题清单（2026-09-15 评审）

> **状态：** 评审清单已进入整改复核；本轮已闭环规则误报、实体截断、缺失 after 状态、LLM 时间预算、DSL-only 和分级故障策略。剩余问题仍以第五节增强项和未闭环的可观测性/知识推理为准。
> **适用版本：** PMKB `1.1.0`、RV 默认 DSL 模式、Guard 插件 `0.7.0-dev`
> **方法：** 全部结论均以代码阅读 + 运行实测取证，命令与原始输出见[附录 A](#附录-a复现命令与实测输出)
> **来源讨论：** ① PMKB 是否算知识库；② 规则搜索/命中如何实现；③ 为什么不用大模型做模糊匹配；④ 大模型"模糊"体现在哪里；⑤ 什么是知识库的推理机
>
> **端到端复核：** 本清单所述问题已按 OpenClaw Hook→PMKB→RV→审批回调→Guard UI 顺序做小规模复现，结果见 [PMKB / OpenClaw Guard 端到端审计报告](./pmkb-e2e-audit-2026-09-15.md)。

---

## 一、结论速览

| # | 结论 | 影响 |
|---|---|---|
| 1 | PMKB 是**策略知识库（policy-as-data）**：声明式、版本化、加载即校验、加载后冻结、可回滚、可溯源；6 类内容里 5 类参与运行时决策 | 「知识库」的说法在工程意义上站得住 |
| 2 | 但按知识表示（KR）的严格定义，它**不是完整知识库**：没有推理机，推理在引擎代码里，且唯一的声明式推理通路（`implies`）**当前 0 条数据** | 评审若追问"你的知识库做了什么推理"，现状答不上 |
| 3 | 规则搜索命中是**确定性流程**：归一化 → 两级候选召回 → 字段级证据比对（四档状态）→ 单调效果合成；无相似度、无 LLM | 这是正确设计，建议在文档里显式写清 |
| 4 | **语义 LLM 路径曾因预算静默失效**：历史 `max_tokens=1024` 已调整为 4096；仍需补降级率指标 | 已修正，剩余可观测性为 P1 |
| 5 | 语义引擎标识（`llm-*` / `builtin-fallback`）**不进审计、无降级率指标** | 静默降级无人发现（本次靠读代码才发现） |
| 6 | 语义 LLM 超时历史上为 10s，当前已调整为 1.5s；后端不可达改为分级降级 | 已修正，仍需真实 Gateway 断连验证 |

### 本轮整改闭环

- `max_tokens` 已调整为 `4096`，LLM 请求超时降为 `1.5s`；超时仍确定性退回本地规则，不阻塞 Hook 主链。
- `rv_rules.json` 的外部群发规则不再仅凭 `external_recipient` 直接阻断；无敏感/跨组织证据时为 `ask`。
- Hook 事件的路径、收件人实体不再固定截断为 8 条；缺失 `after_tool_call` 的旧动作标记为 `failed/unknown`。
- 手写 FSM/`transitions` 已从生产和测试入口移除；历史 `fsm` 配置值归一化为 DSL。
- 后端不可达时改为分级策略：低风险只读放行并审计，高影响工具暂停；`failClosed=true` 仍可全量暂停。

> 2026-09-24 后续变更：上条是当时版本的历史观察。当前 Guard 后端传输不可达时插件对所有 Agent 工具调用静默透传（含写入与执行）；有响应的 HTTP 错误仍按分级错误策略处理。见 [现行 Hook 策略](../features/runtime-hook.md)。
- 新增双浏览器 E2E：OpenClaw resolution → SSE `action.resolved` → Guard 页面状态对账。

---

## 二、PMKB 定位：它到底是什么

### 2.1 与"知识库"定义的逐条对照

| 知识库要素 | PMKB 现状 | 判定 |
|---|---|---|
| 声明式知识表示 | 5 类 JSON + schema 枚举；操作目录是术语表（工具名/别名 → 47 个权限族） | ✅ 但**无形式语义**（无族偏序/包含公理，非 OWL/SHACL；谓词形状由 Python 解释） |
| 知识 / 推理分离 | 规则、关系、Trace 全是数据，引擎只消费 | ✅ 这正是其核心设计 |
| 推理（entailment） | 匹配在 `PolicyEvaluator`、闭包在 `PermissionClosure`、差分在 `PermissionDiff`、组合在 `RiskGraph`——全在代码里 | ❌ PMKB 自身推不出任何新事实 |
| 版本化 / 一致性 | schema `1.1.0` 与 5 个组件版本必须全等；加载即校验（重复 ID、未知操作/端点、引用完整性）；加载后冻结；源码目录与打包镜像一致由测试断言 | ✅✅ 强于一般"策略文件" |
| 解释与溯源 | 每条记录带 `source`、`rollback_state`、正反例；编译产物带 `source_ids`，审计可按 ID 回链 | ✅ |
| 知识获取 / 更新 | 人工编目 + 47 条 `LEGACY-*` 自动迁移；**明确不自动从行为学习写回生产规则** | ⚠️ 有意为之，但获取环节是手工的 |

### 2.2 六类内容里，谁在真正参与决策

| 内容 | 作用 | 运行时是否消费 |
|---|---|---|
| `catalog/operation-catalog.json`（47 操作） | 工具名/别名 → 规范权限族 | ✅ |
| `rules/p0-office.json`（35 原生规则） | 条件 + 处置 + 证据要求 | ✅ |
| `traces/p0-office.json`（29 Trace） | **可执行数据**：`_required_trace_permissions()` 用它定义最小权限边界 | ✅ |
| `relations/p0-combinations.json`（9 组合） | 危险组合超边 → `RiskGraph` + 主体监视器 | ✅ |
| `LEGACY-*`（47，加载时生成） | 迁移/回滚证据，防止新规则弱化历史 hard block | ✅（候选集内） |
| `tests/p0-vectors.json`（29 向量） | 期望值回归 | ❌ 仅 QA 资产 |

### 2.3 **口径建议（重要）**

> PMKB = **版本化权限知识库 / 策略知识包（knowledge base as data）**；规则、关系、最小权限参照均为声明式数据，**推理由评估器、权限闭包、差分与风险图完成**。二者合起来才构成知识驱动系统。

避免两种表述：① 直接称"知识库"却不提推理侧在引擎（评审会追问推理能力）；② 说"有推理机"（当前 `implies` 数据为空，族偏序与一致性检查都不存在）。

---

## 三、规则搜索与命中的实现现状（本次核对）

```
Hook 事件
 → TraceCompiler（归一化：工具→权限族、资源、范围、分类、数量、去向、覆盖度）
 → rules_for_operation（两级候选召回：精确族；无精确则取别名；带 action_type 时追加 47 条 LEGACY）
 → PolicyEvaluator.match_rule（字段级证据比对 → matched / partial / unknown / conflict）
 → evaluate（效果合成：_EFFECT_RANK 单调取最强 + 校准例外 + fail-closed 兜底）
 → 三道门（最小权限差分 / 危险组合 / 覆盖兜底）→ 单调合并 → RV
```

实测（同一份 PMKB 1.1.0）：

| 场景 | 候选 | 状态分布 | 结果 |
|---|---|---|---|
| message.send 外部 11 人 | 2 | matched×2 | `openclaw_approval`，selected=[EX-10, P0-MESSAGE-SEND] |
| message.send 内部 3 人 | 2 | matched×1, conflict×1 | `auto_allow_audit`（EX-10 因 `quantity_mismatch` 出局） |
| file.read 工作区 | 1 | matched×1 | `auto_allow_audit` |
| process.execute 销毁性 | 4 | matched×2, conflict×2 | `block`，selected=[NATIVE-PROCESS-DESTRUCTIVE] |
| unknown_tool | 0 | — | `openclaw_approval` + `unknown` |

**结论：** 判定链路确定性、可回放（`replay_hash`），没有模糊检索成分——这与"不能用大模型做模糊匹配"的设计理由一致（详见[附录 B](#附录-b为什么判定层不用大模型模糊匹配)）。

---

## 四、问题清单

严重度：P0 = 影响安全效果或能力静默丢失；P1 = 影响可观测性/一致性/运维；P2 = 表述与工程质量。

### I-01 [P0][功能] 语义 LLM 路径曾因预算静默失效（已修正）

- **证据**
  - 历史代码 `max_tokens=1024`；当前 `semantic_enhancer.py` 已调整为 `max_tokens=4096`。
  - 实测（同一 prompt，model `deepseek-v4-flash`）：`finish_reason=length`、`completion_tokens_details.reasoning_tokens=1024`、`content` 长度 **0**、`reasoning_content` 长度 4031。
  - `_call_llm()` 中 `if not content: logger.warning("LLM response empty content"); return None` → `evaluate()` 降级 `_local_evaluate()`，结果 `engine=builtin-fallback`。
  - 对照：同样输入把 `max_tokens` 提到 4096 → `finish_reason=stop`（reasoning 1343 + content 706），输出正常。
- **影响（历史）**：模糊语义理解可能静默退回本地规则。
- **当前状态**：预算已修正；空 content 的可观测计数仍属于 E-2。
- **验收**：同一事件返回 `engine=llm-*`，`labels` 含 `contains_secret`，`entities.recipients` 非空。

### I-02 [P1][可观测性] 语义引擎标识不进审计，无降级率指标

- **证据**：`engine/pipeline.py:125` 只写 `event.metadata["semantic"]`；审计落盘的是 `controlled.to_dict()`（`pipeline.py:334`）；`decision.trace` 只有 `pmkb`（`pipeline.py:210`）、`whitelist`（`control.py:36`）、`approval_trust`（`pipeline.py:382`）、`principal_rv`（`services.py:532`）四类阶段，**无 semantic 阶段**。
- **影响**：I-01 这类静默降级无人发现；事后无法统计 LLM 覆盖率与降级率。
- **建议修复**：`decision.trace` 增加 semantic 阶段（engine / scenario / confidence / latency_ms）；增加降级计数与看板。

### I-03 [P1][时间预算] 语义 LLM 超时曾大于 Hook 决策预算（已修正）

- **证据（当前）**：`semantic_enhancer.py` `_DEFAULT_TIMEOUT_SEC = 1.5`，插件同步决策预算为 2 秒。
- **影响（历史）**：语义慢时可能先触发 Hook 超时，导致策略层缺席。
- **当前状态**：超时已压到 1.5s，与 Hook 2s 决策预算对齐；超时确定性退回本地规则，插件不可达时按工具影响面分级。

### I-04 [P2][表述] "向量检索只做候选召回"没有落地实现

- **证据**：全仓 `grep -i "embedding|cosine|similarity|faiss|chroma"` → **0 命中**；PMKB 里的"29 个向量"是回归向量（`policy/data/permissions/tests/p0-vectors.json`），与 embedding 无关。
- **影响**：读者会以为存在 RAG 式检索层；评审追问时拿不出实现。
- **建议修复**：改为"当前无检索层；即使引入，召回结果也不得作为授权依据"。

### I-05 [P1][一致性] 架构文档 `monitor_sources` 示例数字过时（已修正）

- **证据**：`docs/architecture/rv-permission-automata.md` §7 示例写 `behavior 6 / permission 72 / principal 9`；实测 `behavior 8 / permission 82 / principal 9`（82 = 35 原生 + 47 LEGACY）。
- **当前状态**：已更新为实测值 `behavior 8 / permission 82 / principal_permission 9`；其中 permission 82 = 35 条原生规则 + 47 条 LEGACY 回放记录。

### I-06 [P1][schema] `implies` 关系字段与 provenance `source` 冲突，且当前 0 条数据

- **证据**：`policy/permission_diff.py:_implication_edges()` 依次读 `source`/`target`，再退回 `implies: [from, to]`；但 relation 记录里的 `source` **已是来源出处文本**（如 `"P0 office policy"`）。实测 1.1.0 的 9 条关系 = 5 `block` + 4 `openclaw_approval`，**0 条 `implies`**。
- **影响**：闭包的蕴含通路完全空转；若按 `source/target` 写法补数据，会静默不生效或把出处文本误读为权限族。
- **建议修复**：schema 明确规定 `implies` 关系只允许 `{"effect":"implies","implies":[from,to]}`；加载校验断言"边两端必须是已知权限族"；补数据后加回放测试。

### I-07 [P2][架构] 缺少知识库级推理能力

- **证据**：无 Datalog / OWL / SMT 依赖（全仓 grep = 0）；推理在代码中（`PermissionClosure` 前向不动点、`PermissionDiff`、`RiskGraph`）；47 个权限族**平铺无偏序**；**无**语义一致性检查（例如同一族既被蕴含为可放行又被硬拦）；无证明树输出。
- **影响**：`KB 是否成立`这一评审追问缺少支撑；互相矛盾的规则/关系只能靠人工审阅发现。
- **建议路线（择一）**
  - **A. 轻量自研（推荐）**：catalog 增权限族偏序 + `implies` 边；闭包改不动点求值（半朴素 Datalog 风格）；加一致性检查；输出 `derived_from: [edge_id]` 证明链。几百行，保持离线、确定性、可回归。
  - **B. 引入现成引擎**：Datalog（Soufflé/pyDatalog）做闭包与一致性；Z3 做一致性/可达性；OWL + ELK/HermiT 要完备性保证。**只能离线物化，禁止上热路径**。
  - **C. 编译式（已有基础）**：把推理结果也编译进 `PermissionAutomatonCompiler` 产出的监视器，在线只跑状态机。
- **验收**：一条蕴含边改变裁决的回归用例（本次已手工验证：`document.read ⇒ credential.read` 使"读文档 + 外发"命中 `credential-egress → block`）。

### I-08 [P2][元数据冗余] `priority` 字段不参与规则选择

- **证据**：`PolicyRule.priority` 是模型与加载校验的必填字段（`catalog.py:122`）；但 `evaluator.evaluate()` 选择依据只有 `_EFFECT_RANK`（block > approval > allow）与 `score`；`grep priority` 仅出现在定义与校验处。
- **影响**：规则作者可能误以为 priority 决定优先级（尤其同 effect 之间）。
- **建议修复**：要么让 priority 参与同效果内的排序，要么在 schema/文档显式标注"仅元数据/预留"。

### I-09 [P2][语义] `rules_for_operation` 两级互斥：别名规则会被精确规则遮蔽

- **证据**：`policy/catalog.py:rules_for_operation()` —— 存在精确匹配（`match.operation == family`）时，**不返回** `family in match.aliases` 的规则。
- **影响**：为某族新增一条精确规则，潮原本靠别名兜底的规则会静默退出候选集（能力"静默变弱"）。
- **建议修复**：在文档写明这是设计意图，并补覆盖度回归（每个族至少一条精确规则；别名规则单独回归）。

### I-10 [P0][运维] Guard 后端未运行时的分级降级（代码已修正）

- **证据（当前）**：插件 `isHighImpactTool()` 在桥接异常时阻断高影响工具；低风险只读工具才返回 `undefined` 并记录降级日志。
- **当前状态**：Node 运行时回归已覆盖；仍需启动真实 Gateway，采集 before/after 指标（审批量、误拦率、放行率、超时数）。

---

## 五、建议增强（非缺陷）

| # | 增强项 | 价值 | 成本 |
|---|---|---|---|
| E-1 | **语义双路一致性检查**：LLM 与本地规则标签/分类不一致 → `coverage = partial/conflict` → 人工审批 | 语义层单点失手不再静默降级为放行（当前是唯一"可被文本影响"的通道） | 小 |
| E-2 | 语义引擎标识 + 降级率指标进审计与看板 | 让 I-01/I-02 这类问题可被发现 | 小 |
| E-3 | KB 级版本 diff 服务 | "这版改了什么"目前只能靠 git + `source` 字段回答 | 中 |
| E-4 | KB 覆盖度/一致性检查：每个 operation 至少一条规则；relation 端点可达；`implies` 两端已知 | 把 I-06/I-07 的一部分变成加载期错误 | 小 |
| E-5 | 统一时间预算：语义超时 / hook 决策超时 / 熔断阈值 一起定 | 消除 I-03 的倒挂 | 小 |

---

## 附录 A：复现命令与实测输出

```bash
# 以下命令保留为问题发现时的历史复现，仍使用当时的 1024/90s 参数；当前实现为
# max_tokens=4096、LLM timeout=1.5s，请勿据此判断现行配置。
# 1) LLM 模糊路径（合成事件，走 runtime/guard-config.json 的 key）
~/miniconda3/bin/python - <<'EOF'
import json,urllib.request
from openclaw_guard.models import BehaviorEvent
from openclaw_guard.engine.semantic_enhancer import SemanticEnhancer, _build_haystack
h=SemanticEnhancer(); msg="把这份客户名单整理成表格发给王总，只发必要的部分，别带内部备注"
ev=BehaviorEvent(event_id="e1",timestamp="2026-09-15T11:30:00+08:00",action_type="channel_send",
    process_name="openclaw",pid=1,user="u",api_name="message",
    raw_payload={"raw_user_intent":msg}, metadata={"tool_name":"message"})
p=h._build_prompt(ev, msg, "message", _build_haystack(ev, msg, "message"))
body=json.dumps({"model":h.model,"messages":[{"role":"user","content":p}],
    "temperature":0.1,"max_tokens":1024,"response_format":{"type":"json_object"}}).encode()
req=urllib.request.Request(h.base_url+"/chat/completions",data=body,
    headers={"Content-Type":"application/json","Authorization":"***"+h.api_key},method="POST")
d=json.loads(urllib.request.urlopen(req,timeout=90).read().decode()); ch=d["choices"][0]
print("finish_reason:",ch.get("finish_reason"),"| usage:",d.get("usage"))
print("content len:",len(ch["message"].get("content") or ""))
EOF
```

实测输出（`max_tokens=1024`）：

```
finish_reason: length
usage: {'prompt_tokens': 785, 'completion_tokens': 1024, 'total_tokens': 1809,
        'completion_tokens_details': {'reasoning_tokens': 1024}}
content len: 0
```

同一输入 `max_tokens=4096`：`finish_reason=stop`（reasoning 1343 + content 706），语义输出正常。

```bash
# 2) 本地降级 vs LLM 对比（同一事件）
[local] engine=builtin-fallback scenario=channel_send conf=0.6
        labels=channel_present,channel_send,source_internal
        entities.recipients=[]  constraints={}
[llm]   engine=llm-deepseek-chat scenario=channel_send conf=0.92
        labels=channel_send,has_recipient,bulk_send,contains_secret,exclude_internal_notes,scope_limited
        entities.recipients=["王总"]  constraints={"exclude":["内部备注"],"requires_human_review":true}
```

```bash
# 3) 规则命中实测（节选）
message.send 外部 11 人  → 候选 2，matched×2 → openclaw_approval（selected=[EX-10, P0-MESSAGE-SEND]）
message.send 内部 3 人   → 候选 2，matched×1+conflict×1 → auto_allow_audit
process.execute 销毁性   → 候选 4，matched×2+conflict×2 → block
unknown_tool            → 候选 0 → openclaw_approval + unknown
```

```bash
# 4) 蕴含边实验（闭包 + 危险组合）
A. 现状（implies 0 条）：
   已持有闭包=['document.read']，p_after=['document.read','network.egress']，危险组合命中：无
B. 加 implies: document.read ⇒ credential.read：
   已持有闭包=['credential.read','document.read']，p_after 含 credential.read
   危险组合命中：[('credential-egress','block')]
```

```bash
# 5) 规模核对
ops 47 | rules 82（native 35 + LEGACY 47）| traces 29 | relations 9（block 5 + approval 4）| vectors 29
PMKB 编译产物 91 个监视器（session 82 + principal 9）；行为链 DSL 8 监视器 / 61 条链规则
```

---

## 附录 B：为什么判定层不用大模型模糊匹配

1. **代价不对称**：假阳性（危险当安全）是事故，假阴性只是多问一次；而授权语义恰恰住在边界上（`EX-10` 内部消息例外 vs `token-egress` 拦截是"语义近邻、处置相反"）。
2. **对抗性**：请求里带攻击者可控文本（参数、注入内容）。判定输入一旦包含这类文本，"提示注入改判定"就被重新打开；现状只接受规范化证据 + 主机验证身份（`trusted_identity.trust == verified`）。
3. **可审计/可回放**：判定必须回答"命中哪条规则 ID"，`replay_hash` 要求同输入同输出，LEGACY 兼容层要靠"逐条回放一致"才能删。
4. **热路径预算**：后台在 `before_tool_call` 上，决策超时 2s；判定链路目前零网络、纯本地。
5. **无收益**：LLM 的不确定性只能映射到 `unknown → 审批`——最多让判定更严，永远不能让它更合理地放行；而"证据不全不放行"已经把"更严"做完了。规则空间是封闭小词表（47 族 / 82 规则），模糊检索解决的是它没有的问题。

**边界原则：** LLM 可以 `propose / normalize`，不能 `decide`；任何 LLM 输出进入决策路径时，只允许朝"降低放行"方向生效。

---

_最后更新：2026-09-15_
