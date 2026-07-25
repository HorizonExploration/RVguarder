# RV 引擎选型报告（v3）— 新增 Reelay / flloat / RTAMT 对比

**日期**：2026-07-15  
**项目**：OpenClaw-RVGuarder（OpenClaw 个人办公安全插件）

---

## 一、新增候选引擎概述

下表为"别的 AI"推荐的 3 个引擎 + 此前已评估的 transitions/Spot/PyMOP：

| 引擎 | 核心语言 | pip 安装 | 逻辑类型 | 时间约束 | 当前推荐状态 |
|:---|:---|:---|:---|:---|:---|
| Reelay | C++ (纯头文件) + Python 绑定 | ✅ `pip install reelay` | MTL / LTL / STL | ✅ **原生支持** | **新候选** |
| flloat | 纯 Python | ✅ `pip install flloat` | LTLf / LDLf | ❌ 纯事件顺序 | **已存档，不推荐** |
| RTAMT | C++ 后端 + Python 前端 | ✅ `pip install rtamt` | STL（信号时序逻辑） | ✅ 连续信号 | **场景不匹配** |
| transitions | 纯 Python | ✅ `pip install transitions` | FSM（有限状态机） | ❌ 手动编码 | **仍推荐** |
| Spot | C++20 + SWIG 绑定 | ❌ `apt install spot` | LTL / PSL / ω-automata | ❌ 离线操作 | 离线增强层 |
| PyMOP | Java + JPype1 桥接 | ❌ 需 Java 20 + Docker | LTL / ERE / FSM / CFG | ❌ 插桩策略 | 参考设计 |

---

## 二、三个新增引擎的详细分析

### 2.1 Reelay — 最有潜力的新候选

#### 基本信息

| 项目 | 详情 |
|:---|:---|
| 仓库 | https://github.com/doganulus/reelay |
| 安装 | `pip install reelay`（提供 Python 3.9~3.14 预编译 wheels） |
| 许可证 | 待确认（需审阅） |
| 逻辑类型 | **MTL**（Metric Temporal Logic）、LTL、STL、一阶量化扩展 |
| 时间语义 | 离散时间 + 稠密时间双支持 |
| 最新版本 | v25.0.0（2025-12） |
| 论文 | 发表于 arXiv:2604.22384（2026-04），已被正式期刊录用 |
| 架构 | C++ 纯头文件计算图 → 同步数据流系统；Python 为 thin wrapper |

#### 如何在本项目中使用

Reelay 的监控模式非常适合项目的 `rv_trace` 输入：

```python
import reelay

# 创建离散时间监视器
monitor = reelay.discrete_timed_monitor(
    pattern=r"(historically[0:5]{mail_send and external_recipient} -> {block})",
    condense=False
)

# 每收到一个 rv_trace step，调用 update
for step in rv_trace:
    result = monitor.update({
        "mail_send": True,
        "external_recipient": True,
        "contains_secret": True,
        "block": False
    })
    if result["value"] is False:
        print("SECURITY VIOLATION: 向外部发送了敏感邮件")
```

对办公场景（邮件、日报）的优势：

```python
# "邮件外发含敏感内容必须在 3 步内触发阻断"
pattern = r"historically[0:3]{mail_send and contains_secret} -> {eventually[0:3] block}"

# "日报外发给外部收件人必须在 5 步内触发人工审批"
pattern = r"historically[0:5]{report_send and external_recipient} -> {eventually[0:5] ask}"

# "AI 生成内容未经人工审阅不得外发"
pattern = r"G({ai_generated_content and not human_reviewed} -> {block})"
```

Reelay 的 Rye（Reelay Expression）格式直接支持：
- `historically[a:b]{p}` — 在过去 a 到 b 时间单位内，p 一直成立
- `eventually[a:b]{p}` — 在将来 a 到 b 时间单位内，p 终将成立
- `G{p}` — 全局：p 始终成立
- `F{p}` — 最终：p 会在某时刻成立
- `{p} -> {q}` — p 蕴含 q

#### 优势

| 维度 | 评价 |
|:---|:---|
| 部署 | ⭐⭐⭐⭐ — `pip install reelay` 有预编译 wheels，但不是纯 Python |
| 时间约束 | ⭐⭐⭐⭐⭐ — **原生 MTL 支持**，是唯一自然支持"X 分钟内"约束的候选 |
| 在线时延 | ⭐⭐⭐⭐ — C++ 计算图执行，毫秒级 |
| 表达力 | ⭐⭐⭐⭐⭐ — MTL + LTL + STL + 一阶量化，远超当前需求 |
| 文档 | ⭐⭐⭐⭐ — 官方文档完善，有完整教程 |
| 维护 | ⭐⭐⭐⭐ — 2025-12 最新发布，活跃维护 |

#### 劣势

| 维度 | 评价 |
|:---|:---|
| 非纯 Python | ⭐⭐⭐ — C++ 核心，跨平台分发依赖 wheels 覆盖 |
| **许可证** | ⚠️ **待确认** — 仓库无明确 LICENSE 文件，需审慎评估 |
| 初学门槛 | ⭐⭐ — Rye 格式语法 + 时序逻辑概念需要学习 |
| 规则管理 | ⭐⭐ — 规则是字符串模式，无内置规则库管理能力 |
| 业务抽象 | ⭐⭐ — 无邮件/日报原生抽象，需自行建模原子命题→公式 |

#### 约束匹配

| R1 | R2 | R3 | R4 | R5 | R6 | R7 | R8 | U1 | U2 | U3 | U4 |
|:---|:---|:---|:---|:---|:---|:---|:---|:---|:---|:---|:---|
| ✅ | ✅ | ✅ | ✅ | ✅ | ⚠️ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

**R6（初学者友好）判定为 ⚠️**：Rye 格式需要学习，但比 Spot 的 LTL 公式容易理解。

---

### 2.2 flloat — ❌ 不推荐（已存档/死亡）

**仓库状态**：https://github.com/whitemech/flloat — **已于 2022-10 归档（archived）**，read-only。

**最后版本**：0.3.0（约 2021 年）

| 维度 | 评价 |
|:---|:---|
| 安装 | ✅ `pip install flloat` — 纯 Python |
| 逻辑 | ✅ LTLf / LDLf — 有限迹上的时序逻辑，理论上适合本项目的有限工具调用序列 |
| 时间约束 | ❌ 无时间概念 — LTLf 是纯顺序逻辑 |
| 维护状态 | ❌ **已存档归档** — GitHub 仓库已是 read-only，不再接受 PR/Issue |

**为什么不能选**：
1. **已归档死亡**：自 2022 年 10 月起停止维护，Python 版本兼容性无保障
2. **无时间约束**：LTLf 只能表达"先 A 后 B"，无法表达"X 分钟内完成"等时间键约束
3. **仓库所有者 (Whitemech) 已明确放弃维护**

**结论**：不考虑。

---

### 2.3 RTAMT — ❌ 场景不匹配（STL 面向连续信号）

#### 基本信息

| 项目 | 详情 |
|:---|:---|
| 仓库 | https://github.com/nickovic/rtamt |
| 安装 | `pip install rtamt`（最新 wheels 2023） |
| 许可证 | BSD-3-Clause ✅ |
| 逻辑 | STL（Signal Temporal Logic） |
| 维护 | 697 commits，最近更新 2025-11 |

#### 为什么不适合本项目

**核心原因**：STL（信号时序逻辑）面向的是**连续信号监控**，例如：

```python
import rtamt

monitor = rtamt.STLDiscreteTimeOnlineMonitor()
monitor.add_var('temperature', 'float')
monitor.add_var('cpu_load', 'float')
monitor.spec = 'always (temperature > 50.0 implies cpu_load < 0.8)'

# 每步输入是实数值信号
monitor.update(['temperature', 'cpu_load'], [65.2, 0.75])  # ← 浮点信号
```

而本项目的 `rv_trace` 是**离散的布尔标签**（`mail_send` / `contains_secret`），不是连续信号。

| 维度 | 评价 |
|:---|:---|
| 场景匹配 | ❌ — STL 设计用来监控温度、负载、速度等连续数值信号，不是布尔命题 |
| 安装 | ⭐⭐⭐ — `pip install rtamt` 有 wheels，但需注意 Python 版本兼容 |
| 时延 | ⭐⭐⭐⭐ — C++ 后端在线监视 |
| 时间约束 | ✅ 原生 STL 时间支持 |
| 办公场景 | ❌ — 无法自然表达"邮件发送 + 外部收件人"这类布尔组合 |

**RTAMT 的作者 Dejan Nickovic 也是 Reelay 的作者之一**，而 Reelay 统一了 MTL/LTL/STL，更适合本项目的离散事件监视场景。

**结论**：不考虑。

---

## 三、五候选全面横向对比

### 3.1 核心指标对比

| 维度 | transitions ✅ (v2 推荐) | **Reelay ⭐ (新)** | flloat ❌ | RTAMT ❌ | Spot |
|:---|:---|:---|:---|:---|:---|
| **安装** | `pip install transitions` ⭐⭐⭐⭐⭐ | `pip install reelay` ⭐⭐⭐⭐ | `pip install flloat` ⭐⭐⭐⭐⭐ | `pip install rtamt` ⭐⭐⭐⭐ | `apt install spot` ⭐⭐ |
| **依赖** | 零依赖 ✅ | C++ wheels（预编译）⚠️ | 纯 Python ✅ | C++ wheels ⚠️ | C++ 系统库 ❌ |
| **许可证** | MIT ✅ | ⚠️ 待确认 | LGPL v3+ | BSD-3 ✅ | GPL v3 ❌ |
| **时延** | < 1μs ✅ | < 1ms ✅ | < 1ms ✅ | < 1ms ✅ | > 1ms ⚠️ |
| **时间约束** | ❌ 手动编码 | ✅ **原生 MTL** | ❌ 无 | ✅ 原生 STL | ❌ 离线 |
| **办公场景** | ✅ 直接消费 rv_trace | ✅ 需建模为 Rye 公式 | ⚠️ 可建模 | ❌ 信号格式 | ⚠️ 需建模 |
| **初学门槛** | ⭐⭐⭐⭐ FSM 直观 | ⭐⭐ Rye 语法需学 | ⭐ LTLf/LDLf 理论 | ⭐⭐ STL 需学 | ⭐ 极高 |
| **规则管理** | ⭐⭐⭐ Python 对象 | ⭐⭐⭐ 字符串模式 | ⭐⭐ 公式字符串 | ⭐⭐ spec 字符串 | ⭐⭐⭐⭐ 成熟 |
| **维护状态** | ⭐⭐⭐⭐⭐ 10 年活跃 | ⭐⭐⭐⭐ 2025-12 活跃 | **❌ 已归档** | ⭐⭐⭐ 2025-11 活跃 | ⭐⭐⭐⭐⭐ 15 年 |
| **成熟度** | 6.6k stars | 学术/工业双轨 | 小型学术 | 学术 | 工业标准 |

### 3.2 办公场景规则表达能力对比

以关键安全属性为例：**"邮件外发 + 外部收件人 + 含敏感内容 → 阻断"**

| 引擎 | 表达方式 |
|:---|:---|
| **transitions** | Python 对象：`MailSecurityMonitor.feed(props)` → FSM 状态机判定 |
| **Reelay** | Rye 格式：`historically[0:5]{mail_send and external_recipient and contains_secret} -> {block}` |
| flloat | LTLf：`G(mail_send & external_recipient & contains_secret -> X block)` (有限迹版本) |
| RTAMT | STL：`always[0:5](mail_send and external_recipient -> eventually[0:1] block)` → 但需要布尔→浮点映射 |
| Spot | LTL：`G(mail_send & external_recipient & contains_secret → X block)` |

---

## 四、选型结论

### 4.1 两种可行方案对比

| 维度 | **方案 A: transitions** | **方案 B: Reelay** |
|:---|:---|:---|
| 推荐位置 | **RV 主引擎** | **RV 主引擎（若需时间约束）** |
| 本质 | FSM 框架，状态驱动的安全监控 | MTL 引擎，时序逻辑驱动的安全监控 |
| 办公场景覆盖 | ✅ 100% | ✅ 100% |
| 时间约束 | ❌ 需自行实现 | ✅ 原生："5 分钟内" |
| 实现代码量 | ~100 行监视器 + 50 行引擎 | ~30 行 Rye 公式 + 50 行引擎 |
| 初学难度 | 低（面向对象） | 中（时序逻辑语法） |
| 许可证风险 | ✅ MIT | ⚠️ 待确认 |
| 依赖风险 | ✅ 零依赖 | ⚠️ C++ wheels |

### 4.2 推荐：transitions（主推）+ Reelay（可选备选/离线增强）

**核心理由**：

1. **transitions 仍然是当前最稳的选择**：
   - 零依赖、MIT 许可证、纯 Python 嵌入
   - 当前办公场景的约束（邮件外发阻断、日报外发阻断）都是**单步条件判定**，不需要时间键
   - 即使未来需要时序约束，也可以在 transitions 的 `WindowManager` 中手写时间逻辑（如 `time_since_last_event()`）

2. **Reelay 是有价值的备选**：
   - 如果未来需要复杂的**时间窗口约束**（如"附件下载后 5 分钟内外发"），Reelay 的 MTL 原生时间支持会是优势
   - 但许可证需审慎评估，且增加了一个 C++ 依赖层
   - **建议定位**：作为可选`[optional]`的离线增强组件，或二阶段扩展

3. **flloat 已死，RTAMT 场景不匹配**，排除。

### 4.3 最终推荐使用示例（transitions）

```python
# openclaw_guard/integrations/runtime_verification.py
from transitions import Machine
from collections import deque
from datetime import datetime

class MailSecurityMonitor:
    states = ['idle', 'mailing', 'external_send', 'blocked']
    
    def __init__(self):
        self.machine = Machine(model=self, states=self.states, initial='idle')
        self.machine.add_transition('on_mail_send', 'idle', 'mailing')
        self.machine.add_transition('on_external_send', 'mailing', 'external_send',
                                     conditions=['no_secret'])
        self.machine.add_transition('on_external_send', 'mailing', 'blocked',
                                     unless=['no_secret'])
        self._window = deque(maxlen=10)
    
    def no_secret(self):
        return 'contains_secret' not in self._current_props

    def feed(self, **props) -> str:
        self._current_props = props
        self._window.append(dict(props, _ts=datetime.now().isoformat()))
        
        if props.get('mail_send'):
            self.on_mail_send()
        if props.get('external_recipient'):
            self.on_external_send()
        
        return {'blocked': 'block', 'external_send': 'ask'}.get(self.state, 'ok')
```

### 4.4 如果未来需要时间约束（Reelay 参考路径）

```python
# 可选组件
import reelay

class ReelayTimeMonitor:
    def __init__(self):
        self._monitors = [
            reelay.discrete_timed_monitor(
                pattern=r"G({file_download} -> {eventually[0:10] external_send implies ask})"
            )
        ]
    
    def feed(self, props: dict):
        results = [m.update(props) for m in self._monitors]
        return all(r.get("value", True) for r in results)
```

---

## 五、总结

| 引擎 | 结论 | 理由 |
|:---|:---|:---|
| **transitions** | **✅ 主推荐** | 零依赖、MIT、纯 Python、12/13 约束满足 |
| Reelay | ⭐ 备选（二阶段） | MTL 时间约束优势，但许可证待确认 + C++ 依赖 |
| flloat | ❌ 排除 | 已归档死亡，无维护 |
| RTAMT | ❌ 排除 | STL 面向连续信号，非事件/命题格式 |
| Spot | 离线增强 | 维持原定位，GPL v3 + 部署重 |
| PyMOP | 参考设计 | 维持原定位，Java + Docker 部署 |

**一句话结论**：其他 AI 推荐的 Reelay 是**最有潜力的新候选**（MTL 时间约束是独特优势），但综合考虑许可证风险、C++ 依赖层、初学门槛以及**当前办公场景不需要时间键**的实际情况，**transitions 仍然是当前阶段的最优选择**。Reelay 建议作为后续扩展阶段的备选评估对象。
