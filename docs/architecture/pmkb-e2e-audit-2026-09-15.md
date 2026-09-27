# PMKB / RVguarder 端到端审计报告（2026-09-15）

> **审计性质：** 诊断、最小修复与小规模回归复核；修复内容已落地到生产代码并有对应测试。
>
> **对照基线：** [PMKB 问题清单](./pmkb-review-issues-2026-09-15.md)。
>
> **审计目标：** 按“OpenClaw Hook → Guard 事件归一化 → 语义/Trace → PMKB → RV → 控制器 → OpenClaw 审批 → 回调 → Guard 页面”的顺序复现，核对设计是否真正落地，并区分安全缺陷、误报/过度阻塞、同步缺陷和文档问题。

## 一、结论先行

当前项目的主链路可以运行，组件边界基本符合设计：OpenClaw 是 Hook 审批的唯一决策入口，Guard 页面对 Hook 动作只读；PMKB、Authorization Trace、RV 和回调审计都能在同一条请求上留下证据。前端基础冒烟、回调 SSE 测试和后端定向回归均通过。

但“能运行”不等于“设计已经闭环”。本次 E2E 发现并修复了以下优先问题：

1. **后端不可达时的全局放行风险** 已改为分级策略：低风险只读放行并审计，高影响工具暂停，`failClosed=true` 可全量暂停。
2. **外部群发规则误报** 已修正：仅有 `external_recipient` 不再直接 block；无敏感/跨组织证据时进入一次审批。手写 FSM 路径已退役，生产只使用 DSL 生成监视器。

此外还保留 3 类结构性问题：47 个规范权限族中只有 28 个有直接规则；语义降级指标仍待补齐；真实 Gateway 的 after 丢失率与断连行为、SSE 断线重连仍需长期观测。批量收件人/范围的截断缺陷已修复，浏览器基础冒烟已覆盖双引擎，后续只需继续扩展场景覆盖。

## 二、审计范围与方法

### 2.1 覆盖层次

~~~text
OpenClaw Gateway / plugin
        │ before_tool_call
        ▼
Hook token + FastAPI /api/hook/before-tool-call
        ▼
Tool profile → BehaviorEvent → SemanticEnhancer → AuthorizationTrace
        ▼
PolicyEvaluator / PermissionDiff / RiskGraph
        ▼
RuntimeVerificationEngine（默认 DSL）
        ▼
GuardController → ControlledAction / audit / SSE
        │ requireApproval
        ▼
OpenClaw 原生审批中心
        │ onResolution
        ▼
/api/hook/resolve-approval → action.resolved → Guard 页面
        │ after_tool_call
        ▼
/api/hook/after-tool-call → 执行证据与 RV commit
~~~

### 2.2 执行的检查

| 检查 | 结果 |
|---|---|
| PMKB 加载、版本、数量、规则覆盖 | 成功；发现数量/覆盖缺口 |
| Hook 各类工具请求（低风险、破坏性、网络、消息、未知） | 成功；发现批量和范围问题 |
| DSL 同输入判定与历史行为对照 | 成功；外部群发边界已统一为 ask，手写 FSM 已退役 |
| OpenClaw 插件运行态、Gateway 健康 | 插件加载；Guard 端点不可达时按工具风险分级降级 |
| 插件→Guard→回调完整 HTTP 桥接 | 使用匹配 token 的隔离实例成功 |
| Guard UI Playwright | Chromium 5 passed；Firefox 5 passed（清除代理变量、单 worker 复跑；此前并行环境网络错误仅作环境记录） |
| Python 全量测试 | 412 passed / 19 skipped / 4 subtests passed |
| JS/Python 编译、差异检查、VuePress 文档构建 | 均通过（40 页） |

隔离 E2E 中使用过临时目录和临时配置；没有输出或提交任何 token。一次使用不匹配 token 的隔离配置得到 401，作为“配置漂移”证据记录，不把它误报为当前同配置生产故障。

## 三、逐步 E2E 结果

### 步骤 0：运行前提与防护是否真的在线

审计初始诊断结果（修复前观测）为：

- openclaw plugins inspect openclaw-guard-hook --runtime --json：status=loaded、imported=true、hookCount=4，注册 before_tool_call、after_tool_call、gateway_start、gateway_stop，无插件诊断错误。
- openclaw gateway health：Gateway OK。
- openclaw gateway call openclaw_guard.hook_status：guardUrl=http://127.0.0.1:8780、decisionTimeoutMs=2000、failClosed=false、circuitOpen=true。
- curl http://127.0.0.1:8780/api/health 在 2 秒内超时；本机检查未发现 8780 监听进程。

插件代码现在在桥接异常时调用 `isHighImpactTool()`：高影响工具即使 `failClosed=false` 也返回 block，低风险只读工具才返回 undefined 并记录降级日志。`circuitOpen` 只作为健康/恢复状态，不改变高影响安全下限。

**判断：代码已修正；运行态仍需真实部署复核。** 只有确认 Guard 健康、token 绑定和降级指标后，才可采集正式防护效果。

本次收尾检查中，`openclaw plugins inspect openclaw-guard-hook --runtime --json` 仍显示插件
`loaded/imported=true`、4 个 Hook 和 `openclaw_guard.hook_status` 已注册；但
`openclaw gateway health` 对 `ws://127.0.0.1:18789` 返回 `1006 abnormal closure`，本机没有
Gateway 监听进程。因此本轮双浏览器证据来自隔离的 Guard + 插件 HTTP 桥接实例，真实 Gateway
启动后的 before/approval/after 仍需在 Gateway 恢复后复跑，不能将隔离证据标记为生产全链路通过。

### 步骤 1：PMKB 装载与规则覆盖

实测 PMKB 1.2.0（迁移前快照仍保留在本报告历史段落）：

~~~text
operations 47
rules 79 native + 47 migration owners
traces 29
relations 9 = 5 block + 4 openclaw_approval
vectors 29（回归向量，不是 embedding）
implies 0
~~~

对 48 个 canonical operation 调用 rules_for_operation()；当前 native catalog 对高频 OpenClaw 工具均有显式 profile，未命中仍按 unknown→OpenClaw approval fail-closed 处理。迁移前 47/82 的覆盖缺口属于本报告历史快照。

这不是立即的“放行漏洞”：无规则的 operation 通常会进入 unknown → openclaw_approval，安全上偏保守；但它与“每一步都从知识库匹配合规规则”的设计目标不一致，且容易造成常用工具全部弹审批、误报率偏高。当前 PolicyEvaluator 的未知兜底见 [openclaw_guard/policy/evaluator.py](../../openclaw_guard/policy/evaluator.py) 第 103–158 行。

**判断：P1（覆盖度/体验）**。建议把每个 operation 的“有意无规则”显式标注为 approval_by_default，其余补最小规则和正反向向量；不要让“没有规则”和“命中审批规则”共用同一个 unknown 解释。

### 步骤 2：OpenClaw 原生工具建模与 Trace

对 read/write/edit/apply_patch/file_delete/exec/shell/network.request/web_search/web_fetch/browser/feishu.im.send/sessions_* /memory_*/get_goal/update_goal/update_plan/cron/gateway/ask_user/secrets/nodes/computer/canvas/screen/dashboard 等常用名称逐一构造 Hook 请求，结果如下：

| 工具类别 | Trace/动作结果 | 设计对应性 |
|---|---|---|
| 工作区 read、会话/记忆/目标读取 | 映射到相应权限族，低风险读取可 allow | ✅ |
| exec/shell 只读命令 | 映射 process.execute，由参数安全性决定 | ✅ |
| write、edit、apply_patch、file_delete | 映射写/删，默认审批或阻断 | ✅ |
| network.request、web_search、web_fetch、browser | 映射外联/浏览器，默认审批 | ✅ |
| feishu.im.send 内部单消息 | 能归一到 message.send，可走内部低风险例外 | ✅ |
| sessions_send、sessions_spawn、gateway、computer 等高影响操作 | 有 native profile，但许多族无直接 authored rule，最终通常审批 | ⚠️ 覆盖保守但解释不足 |
| 未知 custom_exec/未知 Hook | unknown_tool + operation.mapping，转人工审批 | ✅ 安全兜底 |

本轮复核确认并修复了两个 Trace 质量问题：

1. [tool_hook_bridge.py](../../openclaw_guard/integrations/tool_hook_bridge.py) 不再把 `to`/`from` 当作路径键，消息收件人不会进入 `target_paths`。
2. `_collect_paths()` 与 `SemanticEnhancer._extract_recipients()` 不再硬截断到 8 个值；11 个收件人会完整保留，数量与 `recipient_zone` 一致。

对应回归覆盖消息收件人、路径隔离和完整数量。后续仍需补充更多批量/范围样本，但当前缺陷不会再改变 PMKB/RV 输入。

### 步骤 3：PMKB 判定与 RV 覆盖

#### 3.1 基础场景

| 输入场景 | PMKB/Hook 最终结果 | 预期 | 结论 |
|---|---|---|---|
| 工作区单文件读取 | allow，auto_allow_audit | 放行并审计 | ✅ |
| exec rm ... 破坏性命令 | block，命中 NATIVE-PROCESS-DESTRUCTIVE | 阻断 | ✅ |
| 未知工具 | require_approval，unknown + operation.mapping | 人工确认 | ✅ |
| 内部单消息（单个 to=team@company.local） | allow，低风险例外 | 避免无谓审批 | ✅ |
| 外部批量消息（11 个邮箱） | PMKB/RV 为 openclaw_approval | 仅外发群发应先确认；含密钥/跨组织才阻断 | ✅ |

外部批量案例的修复后 Hook 响应为：

~~~text
action=require_approval
technical_reason=[RV] BroadcastMonitor: ask
PMKB effect=openclaw_approval
rv_result.verdict=ask
recipients=11
~~~

#### 3.2 DSL 规则回放

手写 FSM 路径已从生产代码和测试入口移除，历史 `rule_mode=fsm` 仅归一化为 `dsl`。当前回放结果为：

| 单步 Trace | DSL 结果 | 设计含义 |
|---|---:|---|
| channel_send + bulk_send + external_recipient | ask | 外部群发但无敏感/跨组织证据，交由 OpenClaw 一次审批 |
| channel_send + bulk_send | ask | 批量动作需要确认 |
| channel_send + external_recipient | ok | 单个外部收件人且无高风险证据可继续评估 |
| channel_send + bulk_send + external_recipient + contains_secret | block | 敏感数据外发直接阻断 |

根因是 `broadcasting_external_block` 规则把 `external_recipient` 单独作为阻断条件。本轮已收窄为 `cross_org/contains_secret`，并新增 DSL 回归明确边界。

**判断：已闭环。** 后续规则变更只需维护 `rv_rules.json` 并通过 DSL 回放。

### 步骤 4：OpenClaw 唯一审批与回调同步

使用匹配 Hook token 的隔离 Guard 实例，直连运行时插件完成了以下完整序列：

1. before_tool_call(exec touch ...) 返回 requireApproval，只暴露 allow-once/deny，Guard 页面动作卡没有 approve/reject 按钮。
2. 模拟 OpenClaw onResolution("allow-once") 调用 /api/hook/resolve-approval，HTTP 200。
3. after_tool_call 调用 /api/hook/after-tool-call，HTTP 200。
4. Guard 动作记录最终为 executed，decision_state=allowed，sync_state=callback_received，resolution source=openclaw。
5. Guard SSE 发布 action.resolved；前端事件处理器收到后调用 fetchAction(action_id) 更新卡片，10 秒轮询作为兜底。

这证明“审批权只在 OpenClaw、Guard 只读同步”的主设计已经落地。现有前端冒烟也验证了只读约束和意图摘要/折叠详情。

此前发现的状态一致性缺陷已修复：同一 session 的新 Hook 不再调用成功自动收尾；只有超过 30 秒孤儿阈值且缺失 after 的 Hook 动作才会标记为 `failed/unknown` 并记录 `missing_after_callback`，避免误伤合法并发调用。复现序列（将 action-1 的创建时间推进到阈值之外）为：

~~~text
before(read, session=same)  -> action-1 executing/running
（不发送 after_tool_call）
before(read, session=same)  -> stale action-1 failed/unknown, error_code=missing_after_callback
~~~

这样不会把“OpenClaw 可能尚未执行/执行结果丢失”伪装成成功，审计和跨 session RV 只消费已确认的成功证据。

**判断：已闭环（P1）**。仍需在真实 Gateway 运行中观察 after 丢失率，并校准 30 秒孤儿阈值。

另外，隔离实例使用不同 token 时，插件 before/after 均得到 401；匹配 token 后正常。这说明多实例/重装插件时存在配置漂移风险。Guard 与 OpenClaw 的 token 来源、文件路径和变更后的重载机制应在 doctor/启动检查中显示绑定摘要（不能显示明文）。

### 步骤 5：前端页面与实时同步

Playwright 当前独立 Chromium 与 Firefox 回归各 5 个测试通过。Firefox 首次并行运行曾出现 `NS_ERROR_NET_ERROR_RESPONSE`，清除代理变量并以单 worker 复跑后已形成有效证据：

- RV 开关无刷新切换，Trace 区域随状态变化；
- Skills 页面启停走后端接口；
- Hook 动作在 Guard 页面只读，审批提示指向 OpenClaw；
- 意图摘要存在，详细命令在折叠区展示，命令预览可脱敏。

前端实现上，Dashboard 通过 EventSource('/api/events') 监听 action.created/resolved/updated/timeout/conflict，收到事件后按 action id 拉取详情；SSE 服务端支持 Last-Event-ID，15 秒无事件发送 heartbeat，浏览器自动重连。实现方向与“及时同步”一致。

本轮已新增真实顺序测试：先打开页面监听待确认卡片，再调用 OpenClaw resolution callback，断言 SSE `action.resolved` 后待确认区即时移除卡片。页面仍保留 10 秒轮询作为断线兜底；断线重连和 Last-Event-ID 去重属于后续增强。

**判断：基础链路已闭环（P1）**。不要把前端重新变成第二个审批入口。

### 步骤 6：延迟、语义降级与测试隔离

本地 fallback 的完整 Hook 决策实际约 125–185ms，满足 2 秒 Hook 预算；但配置 LLM 时仍存在基线问题：

- [semantic_enhancer.py](../../openclaw_guard/engine/semantic_enhancer.py) 当前使用 `max_tokens=4096`；历史 1024 预算问题已修正。
- 同文件 `_DEFAULT_TIMEOUT_SEC=1.5`，低于插件 `decisionTimeoutMs=2000`；网络慢时确定性退回本地规则。
- decision.trace/审计没有稳定记录 semantic engine、fallback 原因和耗时，无法从 UI/指标发现降级。
- [main.py](../../openclaw_guard/main.py) 已改为 `load_dotenv(override=False)`，显式进程变量优先，测试可用 `api_key=""` 构造无 LLM 环境。

**判断：时间预算已闭环；语义引擎标识、fallback 计数和真实断连指标仍为 P1 增强项。** 语义层只能做 normalize/propose，不能成为放行依据。

## 四、问题分级总表

| 编号 | 优先级 | 问题 | 证据 | 影响 |
|---|---|---|---|---|
| E2E-01 | P0 | Guard 8780 不可达时的全局放行风险 | 插件健康状态与桥接异常回归 | 已改为按工具影响分级；真实断连待部署复核 |
| E2E-02 | P0/P1 | 外部群发规则误报 | DSL 规则回放与新增回归 | 已收窄为 ask/block 边界，手写 FSM 已退役 |
| E2E-03 | P0/P1 | 收件人、路径混采且固定截断 8 个 | 11 个收件人回归 | 已分离实体并保留完整数量 |
| E2E-04 | P1 | 缺失 after 时自动把旧 executing 动作标为 executed | 生命周期回归复现 | 已改为 failed/unknown |
| E2E-05 | P1 | 47 个权限族仅 28 个有规则 | rules_for_operation 统计 | 常用工具无明确知识库依据，审批噪声高 |
| E2E-06 | P1 | 前端实时回调链缺少顺序覆盖 | 本轮新增 callback/SSE 顺序测试 | 基础链路已覆盖；断线重连仍待补测 |
| E2E-07 | P1 | LLM 语义路径预算倒挂且无降级指标 | 当前 4096/1.5s；Hook 2s | 时间预算已修正，降级指标待补 |
| E2E-08 | P1 | 多实例 token 配置隔离需真实部署复核 | 不匹配 token=401；dotenv override 已修正 | 保留 token binding/doctor 观测项 |
| I-04/I-06/I-07 | P2 | 文档所称向量检索/推理机/implies 与实现不符 | embedding 实现为 0；implies=0 | 评审口径和工程能力不一致 |
| I-05/I-08/I-09 | P2 | monitor 数字、priority、alias 语义需明确 | 基线问题清单已有证据 | 维护者容易误读配置效果 |

## 五、设计对应性判断

### 已对应

- PMKB 是确定性策略数据，LLM 不直接裁决；未知工具走审批而不是放行。
- OpenClaw 是 Hook 审批唯一所有者；Guard UI 不再提供 Hook approve/reject，避免双审批和状态竞争。
- action.resolved 在持久化后发布，降低前端收到事件却读到旧状态的竞态。
- RV 预览不把 pending proposal 写入已执行窗口；成功 after_tool_call 后才提交主体能力状态。
- 插件注册、健康检查、超时、回调、幂等/冲突处理均有明确边界。

### 部分对应或未对应

- DSL 规则已统一为唯一运行时来源；同一步语义由 ChainRule 回放测试固定。
- Trace 的 recipient/path/scope/quantity 已分离并保留完整数量；仍需继续扩充批量与范围场景。
- PMKB operation catalog 比 authored rule 集合大，缺少“有意默认审批”与“遗漏建模”的区分。
- 前端同步已由端到端测试证明 OpenClaw 回调后的即时视觉更新；失败时 10 秒轮询仍是兜底，断线重连需独立验证。
- 运行态采用分级降级：不可达时不阻塞低风险读取，但高影响调用仍保持阻断；正式效果仍需真实部署观测。
- 文档已说明部分历史组件退役，但 PMKB 仍缺少真正的关系推理/证明链；应避免把回归 vectors 描述成向量检索。

## 六、后续最小工作包

本轮 P0/P1 缺陷已完成代码修复，下面是不会扩大实验规模的收尾项：

1. **真实运行观测（P1）**：启动 Guard FastAPI 并重载 Gateway，确认健康状态、token binding、高影响工具断连时的 block；记录 after 丢失率和分级降级计数。
2. **规则覆盖（P1）**：为 19 个无直接规则的 operation 建立“有意默认审批/待建模”清单，优先补 OpenClaw 高频工具，并为每条新增规则配最小正反例。
3. **可观测性（P1）**：在 semantic trace/审计中记录 engine、fallback 原因和耗时，保留 1.5 秒语义预算与 2 秒 Hook 预算的约束。
4. **前端稳态（P1）**：补 SSE 断线重连和 Last-Event-ID 去重测试；Chromium/Firefox 基础冒烟已通过，不新增 Guard 审批入口。
5. **知识库口径（P2）**：动态生成 monitor_sources；将 vectors 统一称为 regression vectors；明确 implies 当前为空，priority/alias 规则写入加载期校验。

### 6.1 测试资产与冗余清查

- 已删除仅服务退役手写 FSM 的 `openclaw_guard/rv/rv_monitors.py`（1045 行）、`tests/test_rv.py`（581 行）和 `tests/test_rv_fsm.py`（420 行）；当前代码、测试与生产依赖均不再引用它们。
- 当前保留 45 个测试模块和 1 个共享工厂辅助文件，共收集 431 个测试项。低数量模块仍有明确门禁职责：OpenClaw 原生工具映射、性能冒烟、P0 回归向量和 LEGACY 逐条回放，均非一次性临时测试。
- `testlab/results/`、`testlab/实验结果/`、`docs/archive/` 和研究夹具按要求作为历史证据保留；其中的旧实现描述已加历史边界，不进入生产导入或现行文档导航。
- 未发现当前代码引用已删除测试或 FSM 模块；后续新增测试必须挂接到现有分层门禁，禁止再创建无复用的一次性脚本。

## 七、验证证据

本轮完成的验证命令及结果：

~~~text
python -m pytest -q
412 passed, 19 skipped, 4 subtests passed

cd e2e && npx playwright test tests/guard-ui.spec.cjs --project=chromium
5 passed（含 callback → SSE → UI 同步）

cd e2e && env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY -u http_proxy -u https_proxy -u all_proxy \
  npx playwright test tests/guard-ui.spec.cjs --project=firefox --workers=1
5 passed（含 callback → SSE → UI 同步）

node --check runtime/openclaw-guard-plugin/index.js
python -m compileall -q openclaw_guard
git diff --check
相对 Markdown 链接审计（排除 VuePress 生成的 `.html` 路由）= 0 个缺失；以上命令均通过

cd docs && npm run docs:build
VuePress build success，Rendering 40 pages
~~~

说明：第一次在受限沙箱执行 E2E 时因不能监听本地端口而得到 PermissionError: Operation not permitted；在获得本地测试端口权限后 Chromium 5/5 通过。Firefox 的并行网络错误属于测试环境问题，已通过清除代理变量、单 worker 复跑得到 5/5 证据。

本报告记录本轮修复后的复核结果；工作区其他已有改动保持原样。后续应补语义降级指标、断线重连和 19 个未直接覆盖 operation 的小规模样本。

> 2026-09-24 后续设计变更：本报告的“后端失联时高影响工具阻断”是 2026-09-15 当时版本的观察，不再描述当前 Hook 策略。当前后端传输不可达时插件对所有 Agent 工具调用静默透传（含写入与执行），Guard 防护暂停；有响应的 HTTP 错误仍按分级策略处理。见 [现行 Hook 策略](../features/runtime-hook.md)。
