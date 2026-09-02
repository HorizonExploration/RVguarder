# 权限建模与端到端架构图

> **用途：** 组会汇报图稿
> **核对日期：** 2026-08-31
> **当前实现基线：** v0.7.0-dev / PMKB 1.1.0
>
> Mermaid 是图稿源格式。VuePress 构建后可直接展示；如需放入 PPT，可使用 Mermaid 编辑器或本地工具导出 SVG/PNG。

## 图一：总体架构与 OpenClaw 审批交接

```mermaid
flowchart LR
    subgraph OC[OpenClaw 运行时]
        H1[before_tool_call]
        H2[工具执行]
        H3[after_tool_call]
        AP[原生审批中心\n唯一批准/拒绝入口]
        RES[onResolution 回调]
        H1 --> H2 --> H3
        H1 -.高风险.-> AP --> RES
    end

    subgraph ING[Guard 接入层]
        BR[tool_hook_bridge]
        BE[BehaviorEvent]
        BR --> BE
    end

    subgraph CORE[Guard 决策后端]
        SEM[SemanticEnhancer\n本地启发式 / LLM]
        TRACE[TraceCompiler\nAuthorization Trace]
        DET[PMKB LEGACY Records\n47 条冻结回放规则]
        POL[PMKB PolicyEvaluator\n覆盖感知规则匹配]
        DIFF[PermissionClosure / Diff]
        RISK[RiskGraph\n危险权限组合]
        RV[Runtime Verification\nDSL 默认 / FSM 回退]
        STATE[Session + Principal 状态]
        CTRL[GuardController\n只升权合并]
        SEM --> TRACE
        TRACE --> DET
        TRACE --> POL
        POL --> DIFF --> RISK
        POL --> RV
        DET --> CTRL
        RISK --> CTRL
        RV --> STATE --> CTRL
    end

    subgraph SURFACE[观察与取证]
        SSE[resolution / SSE / 增量查询\n只读同步]
        UI[Guard Dashboard\n风险解释与状态展示]
        AUD[SQLite / JSONL\nSHA-256 审计链]
        SSE --> UI
        CTRL --> AUD
    end

    H1 --> BR --> BE --> SEM
    CTRL -->|allow / approval / block| H1
    AP -->|用户决定| RES --> SSE
    H3 --> AUD
```

### 讲解要点

- Guard 不修改 OpenClaw 源码，只通过 Hook 接入。
- PMKB 是唯一单步运行时裁决来源；47 条 LEGACY 记录仅保留为可回放兼容数据，RV 负责跨步升权。
- OpenClaw 原生审批页是唯一决策入口，Guard 页面不再创建第二套审批状态。
- `before_prompt_build` 只做审计，不进入 pending approval 队列。

## 图二：权限建模——从工具调用到九维 Authorization Trace

```mermaid
flowchart TB
    EVT[Hook 事件\ntool_name / args / action_type / session_id]
    SEM[语义与确定性解析\nentities / labels / classification / purpose\n命令分类 / URL / 路径 / recipient]
    ID[可信身份边界\nprincipal / agent / capability_lineage\n不可信文本不能直接授予身份]

    subgraph DIM[九维权限本体]
        D1[主体\nprincipal.id/type/trust]
        D2[执行体\nagent_id + capability_lineage]
        D3[操作\noperation.family/tool_id/aliases]
        D4[资源\nresource.type/ids]
        D5[范围\nworkspace / managed / external / unknown]
        D6[数据\npublic / internal / sensitive / secret]
        D7[上下文\nrecipient_zone / purpose]
        D8[覆盖度\ncomplete / partial / unknown / conflict]
        D9[来源\nprovenance / trust / confidence]
    end

    TC[TraceCompiler\n统一字段、解析 canonical operation、保留缺口]
    TR[Authorization Trace\n可追溯的权限证据对象]
    MATCH[PolicyEvaluator\n逐字段证据比对]
    STATUS{匹配状态}
    ALLOW[matched\n可进入低风险基线]
    ESC[partial / unknown / conflict\n审批或阻断，不静默放行]

    EVT --> SEM --> TC
    EVT --> ID --> TC
    TC --> D1 & D2 & D3 & D4 & D5 & D6 & D7 & D8 & D9
    D1 & D2 & D3 & D4 & D5 & D6 & D7 & D8 & D9 --> TR --> MATCH --> STATUS
    STATUS -->|matched| ALLOW
    STATUS -->|partial / unknown / conflict| ESC
```

### 讲解要点

- 工具名不是权限本身，必须先解析为 canonical operation，再补齐资源、scope、数据和上下文。
- `unknown` 不是通配符；缺可信 principal 时不能参与跨 Session 继承。
- 匹配分数只用于解释证据，不作为绕过 `unknown/conflict` 的放行开关。

## 图三：PMKB 知识库设计——规则、证据、关系和回归向量

```mermaid
flowchart LR
    subgraph SRC[权限知识来源]
        CATALOG[operation-catalog.json\n28 operations / aliases]
        RULES[rules/p0-office.json\n31 authored rules]
        TRACE[traces/p0-office.json\n29 最小权限 Trace]
        REL[relations/p0-combinations.json\n9 toxic/conflict/implies]
        VEC[tests/p0-vectors.json\n29 正反例向量]
        LEG[47 DetectionRule\n生成 LEGACY-* 兼容记录]
    end

    BUNDLE[PolicyBundle\n版本化 JSON bundle]
    SCHEMA[schema 校验\nID / operation / version / required fields]
    PARITY[源码目录 ↔ 打包目录 parity]
    FREEZE[递归冻结\n运行时不可变证据]
    EVAL[PolicyEvaluator\n匹配与处置]
    CLOSURE[PermissionClosure / Diff\n最小权限与 scope 扩张]
    GRAPH[RiskGraph\n危险组合关系]
    COMP[PermissionAutomatonCompiler\nPolicyBundle → MonitorSpec]
    TEST[离线回放 / 有限事件样本\n回归与迁移对齐]

    CATALOG & RULES & TRACE & REL & VEC & LEG --> BUNDLE
    BUNDLE --> SCHEMA --> PARITY --> FREEZE
    FREEZE --> EVAL & CLOSURE & GRAPH & COMP
    VEC --> TEST
    LEG --> TEST
    EVAL --> TEST
    COMP --> TEST
```

### 讲解要点

- PMKB 不只是规则列表，而是“操作目录 + 规则 + 最小权限证据 + 危险关系 + 回归向量”的完整策略载体。
- 47 条 legacy 规则已经完成兼容迁移和逐条回放；DetectionEngine 已从生产路径删除。
- 加载器在运行前完成 schema、版本、重复 ID、未知 operation 和 parity 校验，并冻结证据对象。

## 图四：PMKB 编译自动机与端到端执行时序

```mermaid
sequenceDiagram
    autonumber
    participant O as OpenClaw
    participant B as Hook Bridge
    participant T as TraceCompiler
    participant P as PMKB PolicyEvaluator
    participant D as Closure/Diff + RiskGraph
    participant C as PermissionAutomatonCompiler
    participant R as RV Engine
    participant G as GuardController
    participant A as OpenClaw Approval
    participant S as SSE / Audit

    Note over C,R: 启动/加载策略时：PMKB 规则与关系编译为 MonitorSpec
    C->>R: 注册 session 监视器 + principal 监视器
    O->>B: before_tool_call(tool, args, session, identity)
    B->>T: BehaviorEvent
    T->>T: 归一化九维 Authorization Trace
    T->>P: trace + required_fields + provenance
    P-->>D: selected rules / match status / effect
    D->>D: 计算权限闭包、请求差分、危险组合
    D-->>R: pmkb.permission synthetic step + PolicyDecision
    R->>R: session window + principal capability state
    R-->>G: allow / approval / block / risk upgrade
    alt 高风险或证据不完整
        G->>A: requireApproval
        A-->>O: 原生审批卡片
        O-->>A: 用户批准或拒绝
        A-->>G: onResolution
        G-->>S: resolution + trace + audit
    else 低风险且证据完整
        G-->>O: allow
        O->>O: 执行工具
        O-->>S: after_tool_call 审计
    end
    S-->>O: SSE / 增量查询同步到 Guard Dashboard
```

### 讲解要点

1. PMKB 先被编译为标准 `MonitorSpec`，再由 RV 引擎负责窗口、时序和作用域隔离。
2. PMKB 负责“权限结论”，自动机负责“把权限结论纳入运行时监视”；两者不是重复实现。
3. `session-local` 检查当前会话行为链，`principal-global` 检查主体跨会话能力组合。
4. Guard 只升权，不降低既有 `block` 或审批结论；审批结果回到同一条 OpenClaw 生命周期链路。

## 汇报建议

建议按“图二 → 图三 → 图四 → 图一”的顺序讲解：先说明权限如何被建模，再说明知识库如何承载，随后说明如何编译并运行，最后回到系统分层和 OpenClaw 交接。这样“权限建模”是主线，PMKB、自动机和前后端交接分别成为载体、执行机制和落地边界。

相关事实源：

- [权限知识库与 RV 运行时架构结果](./permission-kb-runtime-architecture.md)
- [RV 权限自动机架构](./rv-permission-automata.md)
- [前后端交接改造报告](./frontend-handoff-redesign-report.md)
- [项目理解与当前记忆](./project-memory.md)
