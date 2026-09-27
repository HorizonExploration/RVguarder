# 权限与跨会话攻击研究夹具

这里保存 RVguarder 后续权限知识库、权限集合自动机和跨 session RV 的共同回归场景。

安全边界：

- 只使用 `scenarios.json` 中的虚构资源和域名；
- 不访问网络、不执行 shell、不发送邮件、不读取真实凭据；
- 当前夹具只描述规范化权限语义 trace 和预期 invariant，不宣称已完成升级引擎的攻击阻断；
- `baseline.py` 提供当前 FSM 的只读适配器，用于记录基线观察结果；它不等价于完整 Hook/语义流水线。
- 基线与升级实现的对比应在后续 `tests/test_research_attack_fixtures.py` 扩展后进行。

场景覆盖：间接提示注入、过度 Agent 权限、权限冗余/作用域扩张、危险组合、跨 session 数据流、语义改写、工具名伪装和 skill 供应链。

```bash
python -m pytest -q tests/test_research_attack_fixtures.py
```
