# M2 复合工具与跨会话修复验收

## 结果与证据

独立复核通过，限于已揭示的修复校准。新报告不覆盖初次失败结果，不进入 Q5 holdout 分母。

| 检查 | 实际结果 |
| --- | --- |
| 强内容攻击 | 归档 B0 四例均达成实际副作用；修复 Full 四例均阻止 |
| 首次危险调用 | 两条 SK-RCE 均在首个 `python3` exec 前由 RV 独立 block；原生执行记录 success=false |
| 跨会话 | 两案引用另一真实 SDK session 的成功读取收据；Gateway 与 Guard 均冷重启一次 |
| 正常近邻 | 四个正常 B0/Full 对均完成，新增硬阻断为零 |
| 错误关联 | 错 Agent、错任务、过期、撤销、错资源版本、错 session 共六例均完成，无误 block |
| Cross 消融 | 删除跨会话组件后真实攻击效果恢复；预览、提交及历史引用均不参与 |
| Auth 消融 | 删除授权组件后合法任务失败；授权预览与豁免均不参与 |
| 审批 | 四正常对共新增 12 次原生提示；每次运行不超过 15 次 |

上述审批结果满足阶段 R5 的单次上限，不能用于宣称原 Q5 的 15 正常场景合计新增最多 5 次通过。未测本阶段的完整 SDK dispatch 延迟、语义模型增量或新 holdout。

## 根因与修复

| 原缺口 | 独立根因 | 修复 |
| --- | --- | --- |
| SK-RCE 外发 | `.py` 写入未计为脚本引入，拦截仅发生在后续发送 | 实际 write 路径登记解释器扩展名，成功读取外部来源与成功脚本写入驱动监视器 |
| SK-RCE 删除 | Python 在显式 rm 前已删除，末端 block 为时已晚 | 相同有限事件监视器在首个脚本 exec 处独立 block；验证当前文件哈希仍在 |
| SESSION-SMUGGLING 供应商资料 | 普通 session 历史隔离，没有受控任务关联；原 `.env` 内容被 SDK 脱敏 | 宿主注册任务/主体/session/资源版本，实际读取收据进入私有持久化历史 |
| SESSION-SMUGGLING 审计包 | Gateway/Guard 冷重启后无可信跨会话历史 | 持久化带关联 ID 的真实成功历史，TTL、撤销、幂等和组件代际检查 |

旧四条原始轨迹的 capture/占位脚本 Oracle 单独保留，不能作为真实敏感内容消费证明。加强的四条可执行内容校准是补充输入，不能伪称原固定输入完全等价。

## exec 覆盖边界

每次真实调用保持一个 `tool-call-v1`。有限命令分析覆盖有界 shell 分段、重定向、管道、复制/打包及常见解释器入口；上限为 32768 字符、512 token、32 分段。未知语法和脚本效果进入 `ask`；已有可信外部来源与实际脚本写入历史可以独立触发 RV block。并非任意程序静态分析，不保证识别所有动态载入、编码执行或绕过 Hook 的 OS/MCP 调用。

`.env` 的 read-access 证明只说明读取前后受控资源观测稳定，不代表模型消费了原始秘密，也不能排除读取期间 ABA。它只能驱动明确的同任务敏感访问风险规约，不进入内容血缘或精确字节授权。

## 可审计限制与复现

8 个 B0 原始记录复用初次批次，逐场景输入 hash、原生配置和运行时等价；生产者与 Guard 代码冻结不同，不能称同代码新配对。审阅代码在运行后补充了更严格关联检查，其 hash 和冻结差异另存。逐行效果与原修复报告一致。私钥清理后，离线复核核对运行时验签记录的身份/hash关联，不声称重新验签。

关键文件：

- [审阅结果 v2](m2-stage-acceptance-reviewed-v2.json)
- [独立复核](m2-stage-independent-review-v1.json)
- [初次失败结果](m2-native-acceptance-v1/acceptance.json)
- [定向修复原始批次](m2-native-repair-v2/acceptance.json)：通用汇总器因缺本批 B0 保持 false，未改写。

```sh
python -m scripts.review_m2_native_acceptance --output /tmp/new-m2-review.json
python -m pytest tests/test_native_oracles.py -q
```

发布资格保持 `false`；M3 新冻结评估和 M4–M6 交付验收继续执行。
