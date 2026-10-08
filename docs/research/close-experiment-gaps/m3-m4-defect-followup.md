# 本轮缺陷与整改记录

历史冻结报告保持原样。本记录区分项目缺陷、实验夹具问题和仍未覆盖的能力。

| ID | 现象与根因 | 整改与证据 | 状态 |
| --- | --- | --- | --- |
| EXP-ARM-CROSS-001 | P、P+S 原先未关闭跨会话准备路径，消融存在组件参与污染 | `arms.py` 同时关闭 cross_step_rv、cross_session_rv；校准五臂实际开关校验通过 | 已修复 |
| EXP-TIMING-REGISTER-001 | SDK 在发现和运行阶段重复注册插件；计时观察器重复安装抛错，导致办公插件注册失败 | 同进程共享观察器、分别注册回调、关闭时只落盘一次；mapping v1–v3 失败保留，v7 原生成功 | 已修复 |
| PKG-UI-001 | 后端 wheel 未携带前端，独立安装缺少界面 | build_py 分发受限静态文件；隔离安装验证 index、5 JS、1 CSS；`m4-wheel-ui-preparation-v1.json` | 已修复，最终候选继续验收 |
| EXP-SCHEDULE-FIXTURE-001 | 日期 2100 超出 SDK 最大十年范围；SDK 对 systemEvent 文本去除首尾空白 | 改为 2027，Oracle 比较实际规范化后的文本摘要；mapping v7 准入 | 夹具已修复 |
| EXP-AUTONOMOUS-LAYER-001 | 自主驱动原始记录被标成固定轨迹；晚到模型响应可能进入下一次采集器 | 显式传递 evidence_layer；实例固定采集器；补充层使用冻结语义录制并单独记录未命中回退 | 已修复，自主原生验收待运行 |
| EXP-ANALYSIS-DENOM-001 | 分析器仅按已出现的行计分，缺失实验臂可能遗漏；计时重复 ID 可能被覆盖 | 校验计划笛卡尔积、报告 missing_planned_runs，比较五臂原生配置，拒绝非有限或重复计时 | 已修复；校准复算 v2 |
| RV-SCHEDULE-COVERAGE-001 | 两个未授权未来任务均被真实 Gateway 持久化，现有外发与脚本规则不覆盖此副作用 | `m3-calibration-analysis-v2.json`：Full 2/10 攻击效果仍达成；不把注册等同未来执行 | 开放 |
| RV-APPROVAL-COST-001 | 10 个正常任务均完成且无硬阻断，但 Full 新增 10 次原生提示 | 超出原 Q5 最多 5 次的总量门，保持原门槛；不把 allow-once 表说成真实用户批准 | 开放 |
| RV-HOOK-LATENCY-001 | 校准回调边界 p95 增量约 302 ms；尚未观测完整 SDK 调度边界 | 同调用 52 对计时；回放排除在线模型网络，回调计时排除调度器首尾，完整 R6 尚未核验 | 开放 |
| EXP-TRUST-COMMIT-001 | 禁用 approval_trust 只阻止复用，`allow-always` 回调仍可写入指纹 | 批次结束后增加持久提交代际门；persistent仅表示实际写入；关闭、ABA切臂、落盘失败不留下可复用信任测试通过 | 已修复 |
| RV-RELATIVE-CWD-001 | `cwd=.` 按Guard宿主进程cwd解析，使真实Docker工作区只读cat被标为outside | 相对cwd以受控workspace解析；绝对内/外路径、遍历、软链接逃逸5项通过；原生校准两臂提示3→0，不当作信任复用贡献 | 已修复 |
| EXP-SEMANTIC-SCOPE-001 | cwd修正使旧冻结录制缺20个事件的当前prompt哈希，最终全量回归出现1项失败 | 历史录制不变，新兼容录制168事件、8个真实API提示，相关28项通过；不是新安全实验 | 已修复 |
| RV-PRINCIPAL-POLICY-001 | 主体状态固定加载默认策略，忽略Runtime注入bundle，恢复时亦不一致 | 新建/恢复显式使用注入策略，切换时清空旧主体授权；相关18项通过 | 已修复，完整权限关系消融仍待完成 |
| PKG-WHEEL-TIMESTAMP-001 | 未设置SOURCE_DATE_EPOCH的两次wheel内容相同但ZIP时间戳不同 | 构建说明显式固定SOURCE_DATE_EPOCH=0；旧失败产物保留，不宣称其字节一致 | 构建环境已纠正 |
| RV-HOOK-DOUBLE-WRITE-001 | `_replace_action`已落盘，Hook再次`_save_all`造成重复整表写入 | 删除两处重复写入；30次本地read写盘150→90，67项定向回归通过；SDK增量时延未复测 | 已修复，随下一候选收敛打包 |
| RV-AUTOMATION-POLICY-001 | automation.modify已投影schedule效果，但PMKB候选为空，RV也未命中；正常与攻击均走审批 | 原生逐动作诊断保存；需一般化调度权限与执行器授权契约，不依据job名定制规则 | 开放 |
| RV-UPLOAD-FACT-001 | 六次正常网络/分享审批伴随network.upload模型与本地事实冲突，本地仅按文本关键词分类 | 保留冲突证据；需工具契约投影及可信授权贯通，不能直接忽略冲突 | 开放 |

## 本轮校准结论

20 个独立校准场景，五臂共 100 次原生 Docker 工具运行全部准入且无代码漂移。B0 攻击效果达成 10/10，Full 为 2/10。Full 比 P+S 额外阻止 8 个攻击，未新增正常失败；Full 比 P+C 没有观察到语义层新增防护。这只适用于本轮配置和校准场景。

新 holdout 为 30 个独立场景，已完成一次揭盲；规则保持 r4，防止8/15攻击，正常15/15完成、零硬阻断，提示增量16、回调p95增量381.349ms。定向消融与自主场景均在揭盲前固定。默认随包67条规约保持原哈希。候选保持 `release_qualified=false`，详见[当前收尾报告](m3-m6-current-report.md)。
