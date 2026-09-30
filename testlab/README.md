# 历史实验与研究夹具

已移除过时的 A/B/C 脚本、AgentDojo 三 Arm 执行器及其绑定测试、方案和环境说明。归档中的旧评测脚本也已从工作树清除；需要追溯时可从 Git 历史读取。这些实现依赖已退役的检测路径，或无法为当前 PMKB、三态 RV 和单一 OpenClaw 审批链提供可复现结论。

每项实验在工作树中只保留最终成套产物；被替代的运行记录可从 Git 历史追溯。AgentDojo 升级评测保留 `results/agentdojo-upgrade/20260830T123022Z-combined/`，办公回放保留 `results/office-value-v3-foundation/`、`results/office-value-v3-rv-gate-reviewed/` 和 `results/office-history-rv-calibration-v1/`。

保留内容：

- [`results/`](results/README.md) 与 `实验结果/`：各独立实验的最终原始数据、报告和图表；历史结果只作研究过程证据，不能作为当前安全效果结论；
- `research/`：无网络、无真实凭据、无实际工具调用的本地权限/RV 场景夹具。

当前仓库的可执行基准是 `office_chain/`（见下）；其余历史评测不可执行。新的实验设计须先明确假设、对照、执行语义与样本规模，再新增独立的可回放夹具和测试门禁。

当前的小型个人办公价值重放位于 `office_value/`，运行方式见其 README；它不执行真实工具或网络请求。

链式攻击防护价值实验位于 `office_chain/`（office-attack-chain-v1）：6 个公开事件族 × 48 个独立场景、五臂消融（`B0`/`P`/`P+S`/`P+C`/`Full`）、预注册 G1–G5 门槛。它在**真实 OpenClaw 运行时 + Docker 沙箱 + 合成办公插件**上执行，外部副作用只写本地 receipts（无真实网络出站、无真实凭据、无真实 shell 提权），Agent 行为来自冻结轨迹 provider、语义来自冻结录制。运行方式、产物清单与证据边界见 `office_chain/README.md`；该套件是唯一提供可执行大规模基准的入口。
