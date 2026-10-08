# M1 逐规则类型化授权守卫

## 已实现

DSL新增 `ChainRule.unless_authorized`，限定一个具体办公工具及有限操作族。它只能用于没有 `to_state` 的终端 block 条件，不修改历史状态迁移，也不关闭其他规则或监视器。默认规则文件保持不变。

`VerifiedCallAuthorization` 是可信宿主checker返回的类型，不从HTTP、附件、工具参数、模型标签或字典恢复。守卫检查单次step/run/call、主体/Agent/session、工具/操作、原参数哈希、接收方、规范资源引用、完整内容范围、五分钟期限及事实生成时的组件代际。checker接收有界只读副本；异常、不确定或错误类型均保留原block。

运行引擎默认 `authorization_checker=None`。现有执行前证明后台诊断仍为 `decision_eligible=false`，没有接成可信checker，也没有开启生产授权例外。真实checker必须在受控执行器和当前授权/撤销边界验收后接入，且不得在热路径无界等待IO。

## 独立block与审计

- 明确授权只令指定条件不触发；同监视器另一条block仍可触发。
- 实际pipeline中，单步allow/ask仍可由其他RV规则升为block；PMKB硬block不被降级。
- `authorization_exceptions`返回指定rule/step/grant/snapshot/task，区别“未命中”与“命中后例外”；参数化监视器同样提供证据。
- 这些诊断不写入可恢复的授权历史。恢复后没有checker时，不凭旧诊断放行，也不通过旧守卫的状态迁移污染新步骤。
- Auth关闭不调用checker；关闭再开启后，旧代事实拒绝，新代重新核验的事实才能参与。

## 验证与缺陷

相关五个Python模块120项通过，最后补充新代事实正向检查后守卫模块27项通过。全量回归920通过、20跳过、4个subtests通过；另有一条既有测试客户端弃用警告。覆盖伪造字典/标签、错身份/参数/接收方/资源、过期/部分内容/未知效果、checker突变、组件切换、其他RV/PMKB block、普通及参数化审计与恢复。

独立审查指出并已修复：授权例外缺少运行层审计；guard允许状态迁移导致撤销后重放改变历史状态；缓存事实缺少生成代际。最终独立复核通过，独立五模块86项通过。本轮审查与测试均仅覆盖库能力及受控checker夹具，不构成真实安全场景结果。

## 尚未完成

真实checker生产适配、撤销后执行边界、SDK完整身份、密钥/执行器隔离及正常完成收据仍待验收。非规范路径或非原样URL不会扩大授权，保守保持block，相关正常使用代价需在calibration中测量。

此前Docker WSL代理不可用；2026-10-06后续检查已恢复29.8.0，并取得三个办公sink的真实调用收据，见[原生契约进展](m1-native-contract-progress.md)。授权及完整阶段验收仍未完成。

**M1尚未通过；M2–M6未完成，未新跑矩阵、未使用模型API、未发布。**
