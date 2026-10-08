# M1 执行快照与实验臂隔离

## 已实现

办公模拟插件新增默认关闭的宿主配置 `snapshotExecution`。三个有限办公工具在真实 before 回调中固定文件或 body 的 Buffer、原参数哈希、SDK call/run/Agent/session。执行时只消费该 Buffer，参数或接收方变化、缺失/歧义上下文、过期、重复消费及不可读资源在第一条副作用收据前失败。文件引用不能回退到 body。

这是原生工具执行契约，不签发授权，也不是 Guard 后端故障阻断策略。正式配对实验须让所有臂使用相同契约配置；历史基线仍保持默认关闭，历史分母及成绩不变。

预算为每份内容最多 1 MiB、最多 16 个待执行快照、有效期五分钟。参数先检查扁平 string/boolean 契约与字符/UTF-8预算，再计算哈希。文件以 fd 读取并核对打开后的路径、regular-file 类型及读前后大小/时间；FIFO不会等待。

组件配置现在有单调代际。后台核验在提交时及最终内存写入时检查同一代际；关闭再开启不能复用旧代际。旧臂记录/诊断不能被新臂读取，新臂同 call 键可独立提交，旧记录不占用新臂容量。直接提交接口同样检查 Auth 门。正式消融仍采用独立实例与存储。

## 验证

```sh
python -m pytest tests/test_content_receipts.py tests/test_content_flow.py tests/test_host_authorization_bridge.py tests/test_native_content_receipts.py tests/test_experiment_components.py -q
node --test testlab/office_chain/native_office_plugin/index.test.mjs testlab/office_chain/native_office_plugin/execution_snapshot.test.mjs
```

本轮 Python 75 项、Node 9 项通过。新增检查覆盖三个 sink 的审批期间换文件、换接收方、缺失/歧义调用、FIFO、超限文件、参数预算、容量、过期、单次消费及跨臂竞争。测试直接执行 Node 插件，尚未运行真实 Agent；不计入安全实验分母。

独立只读复核最终无新增必须修改项；复验其中四个 Python 模块 66 项与 Node 9 项通过。冻结台账校验无错误，旧 DSL SHA-256仍为 `496daa04a0bd532d9f99eaaa6293e1f52505dc5f9b098cc94f0af40bb5c255a7`。

## 尚待验收

- 普通文件同步 I/O可能阻塞；`O_NONBLOCK` 不保证 regular-file 低延迟。须建立有界准备阶段并测量实际 Hook 边界。
- execute 接口只收到 call ID；完整 run/Agent/session 来源及并发关联须在实际 OpenClaw 实例中验证，不能凭本地回调夹具宣布可信身份成立。
- 尚无签名的执行前快照证明传入 Guard，不能把参数哈希或异步参考观察作为授权放行事实。
- 尚缺真实 Docker 执行器/密钥隔离、撤销时效、类型化 DSL 授权守卫及正常任务实际完成收据。

旧 DSL 哈希保持不变，未增加全局 RV 降级门。**M1 尚未通过；本轮未重跑安全矩阵或调用模型 API。**
