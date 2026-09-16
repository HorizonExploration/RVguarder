# 阶段 A：IR 结构化透传 实施计划

> **历史计划（2026-08）：** 本文保留阶段 A 的设计与验收记录，不是当前实施规范。RV 已收敛为 ChainRule DSL-only，手写 FSM 及旧测试文件已移除；当前回归入口为 `tests/test_runtime_verification.py` 与 `tests/test_rv_dsl.py`。

## 摘要

在 `openclaw_guard/rv/ir.py` 新增 Pydantic 数据模型（`Entity`/`Constraint`/`ToolCallIR`），修改 `semantic_enhancer.py` 的 LLM 和本地两条路径，使 `rv_trace` 每个步骤透传结构化实体、约束与置信度字段，同时保持原有 `props` 标签不变以确保向后兼容。

## 当前状态分析

### 现状
- `semantic_enhancer.py` 的 `evaluate()` 返回 `{"semantic": {...}, "rv_trace": [{"step_id","event","props"}]}`
- LLM 路径 (`_call_llm`)：在 `rv_trace` 每条步骤只补全 `step_id`/`event`/`props`（[semantic_enhancer.py#L212-L217](../../openclaw_guard/engine/semantic_enhancer.py#L212-L217)），LLM 返回的 `semantic.entities`/`semantic.constraints`/`semantic.confidence` 信息未写入 rv_trace
- 本地路径 (`_local_evaluate`)：`_local_evaluate` 已内部分析出 `recipients`、`constraints`、`confidence`（[semantic_enhancer.py#L350-L390](../../openclaw_guard/engine/semantic_enhancer.py#L350-L390)），但仅存于 `semantic` 字段，未透传到 `rv_trace` 步骤
- 下游消费者（`pipeline.py` 的 `_annotate_event_context`、`_apply_rv_if_available`）只使用 `rv_trace` 列表，不消费额外结构

### 目标
- 新增 `rv/ir.py`：定义 `Entity`、`Constraint`、`ToolCallIR` 三个 Pydantic 模型
- `_call_llm`：从 LLM 返回的 `semantic.entities`/`semantic.constraints`/`semantic.confidence` 提取结构化字段写入每条 `rv_trace` 步骤
- `_local_evaluate`：将本地已提取的 `recipients`/`paths`/`urls`/`constraints`/`confidence` 写入 `rv_trace` 步骤
- `props` 字段原样保留，zero break change

## 详细变更

### 1. 新建 `openclaw_guard/rv/ir.py`

**内容**：三个 Pydantic 模型

```python
# Entity: 语义分析提取的实体信息
class Entity(BaseModel):
    kind: str          # "recipients" | "paths" | "urls" | "tool_name"
    values: list[str]  # 实体值列表

# Constraint: 语义分析提取的约束条件
class Constraint(BaseModel):
    kind: str          # "exclude" | "time_range" | "scope" | "human_review"
    value: str | bool  # 约束值

# ToolCallIR: 单条 rv_trace 步骤的结构化中间表示
class ToolCallIR(BaseModel):
    step_id: str
    event: str
    props: list[str] = []
    entities: list[Entity] = []
    constraints: list[Constraint] = []
    confidence: float | None = None
```

**理由**：
- Pydantic BaseModel 与项目现有 `models.py` 风格一致
- `entities`/`constraints`/`confidence` 全部可选默认空，向后兼容
- `ToolCallIR` 的 `props` 保留原位置，下游所有基于 `props` 的代码零修改

### 2. 修改 `semantic_enhancer.py` — LLM 路径

**文件**：[semantic_enhancer.py](../../openclaw_guard/engine/semantic_enhancer.py#L132-L219)

**变更点**：在 `_call_llm` 方法的 rv_trace 补全循环中（第 212-217 行），为每条步骤注入结构化字段：

```python
# 在 item.setdefault("props", []) 之后新增
# 从 semantic 中提取实体列表
semantic_entities = _build_entities(semantic.get("entities", {}))
semantic_constraints = _build_constraints(semantic.get("constraints", {}))

for item in rv_trace:
    ...
    item.setdefault("entities", semantic_entities)
    item.setdefault("constraints", semantic_constraints)
    item.setdefault("confidence", semantic.get("confidence"))
```

**注意**：`_build_entities` / `_build_constraints` 作为同文件内私有函数，负责将 `semantic.entities` 字典（`{"paths": [...], "urls": [...], "recipients": [...], "tool_name": null}`）转换为 `Entity` 列表、`semantic.constraints` 字典转换为 `Constraint` 列表。此时只做结构转换，不引入 IR 模型依赖（避免可选依赖问题 — semantic_enhancer 在 legacy 模式下也需要可用，而 ir.py 依赖 pydantic，但 pydantic 已在项目核心依赖中）。

### 3. 修改 `semantic_enhancer.py` — 本地路径

**文件**：[semantic_enhancer.py](../../openclaw_guard/engine/semantic_enhancer.py#L342-L390)

**变更点**：在 `_local_evaluate` 的 `rv_trace` 构建处（第 383-389 行），注入已本地提取的实体和约束：

```python
"rv_trace": [
    {
        "step_id": "s1",
        "event": scenario or event.action_type,
        "props": sorted(labels),
        "entities": [
            {"kind": "recipients", "values": recipients},
            {"kind": "paths", "values": list(event.target_paths)},
            {"kind": "urls", "values": list(event.network_targets)},
            {"kind": "tool_name", "values": [tool_name] if tool_name else []},
        ],
        "constraints": [
            {"kind": k, "value": v}
            for k, v in constraints.items()
            if v not in (None, [], False, "")
        ],
        "confidence": semantic["confidence"],
    }
],
```

**理由**：`_local_evaluate` 已经在同一函数中提取了 `recipients`（第 351 行）、`constraints`（第 352 行）和 `confidence`（第 378 行），只需在 rv_trace 步骤中透传即可，不再需要额外函数调用。

### 4. 新建 `tests/test_ir.py`

**内容**覆盖：
- `ToolCallIR` 实例化（最少字段）、实体/约束为空时断言
- `ToolCallIR.model_dump()` 输出包含所有字段
- 从 `ToolCallIR` 列表构建 rv_trace 的模拟场景

### 5. 回归 `tests/test_semantic_enhancer.py`

**确保**：
- LLM 成功路径测试（`test_llm_success_path_uses_llm_engine_tag`）新增断言 rv_trace[0] 含 `entities`/`constraints`/`confidence`
- 本地降级测试（`test_llm_failure_falls_back_to_local_rules`）同上
- `props` 字段值不变

## 假设与决策

| 项 | 决策 | 理由 |
|---|---|---|
| 数据模型技术 | Pydantic `BaseModel` | 与项目 `models.py` 风格一致，pydantic 已在核心依赖中 |
| 实体/约束存储格式 | 字典列表 `[{"kind":...,"values":...}]`，而非强类型 Entity 对象 | rv_trace 当前是裸字典列表，在 rv_trace 步骤中直接存 Entity 对象会破坏 JSON 序列化路径（审计存储等）。IR 模型仅在类型标注和构建时使用，存储时保持可序列化的字典结构。 |
| 每条 rv_trace 步骤的 entities | 全部步骤写入相同的全局实体集 | LLM 按事件语义分析一次，各步骤共享同一组实体/约束。若未来需要步骤级粒度，可通过子步骤 entity_key 区分。 |
| `props` 保留 | 原样保留 | spec.md 明确要求向后兼容，下游监视器全部基于 `props` 做 FSM 判定 |
| `_call_llm` 中 _build_entities 实现 | 同文件私有函数（纯 dict→list 转换） | 避免 semantic_enhancer 在 import 时依赖 ir.py（遵循项目 "可选依赖不能成为 import-time 强依赖" 的原则），ir.py 仅由约束引擎等下游消费者显式导入 |

## 验证步骤

1. `python -m pytest tests/test_ir.py -q` — 新模型测试通过
2. `python -m pytest tests/test_semantic_enhancer.py -q` — 回归通过，新字段存在
3. `python -m pytest tests/test_runtime_verification.py tests/test_rv_dsl.py -q` — 当前 RV 层回归
4. `python -m pytest tests/test_pipeline.py -q` — 流水线端到端无变化
