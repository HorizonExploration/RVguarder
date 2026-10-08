# 问题—措施—验收—证据映射

状态：M0 独立复核通过；输出证据为待交付要求，不是已完成声明。判据以 [acceptance.json](acceptance.json) 为准。

|问题|里程碑|措施|验收|输出证据|
|---|---|---|---|---|
|PREC-001|M1|可信资源版本/来源关联，分开违规block、授权不明ask与合法共享|R1/R3/R4；公开摘要收据+攻击无敏感外发收据|docs/research/close-experiment-gaps/m1-verification.json + 对应测试/结果包原始记录（待执行，不代表已经存在）|
|TIME-001|M2|独立定位首个越权副作用，提前到真实执行前边界|R1/R2；实际状态及收据|docs/research/close-experiment-gaps/m2-verification.json + 对应测试/结果包原始记录（待执行，不代表已经存在）|
|EXP-001|M0|保留失败原始记录和恢复记录，补充原生裁决诊断|未应用审批不得算防护；恢复运行不增加安全分母|docs/research/close-experiment-gaps/m0-verification.json + 对应测试/结果包原始记录（待执行，不代表已经存在）|
|EXP-002|M0|保留已实现的受限裁决错误诊断并验证脱敏|既有回归及诊断允许字段，不输出工具内容|docs/research/close-experiment-gaps/m0-verification.json + 对应测试/结果包原始记录（待执行，不代表已经存在）|
|COV-001|M2|独立复现SK-RCE外发，确定exec路径与首次副作用|R2 4/4中的独立一例，无越权外发收据|docs/research/close-experiment-gaps/m2-verification.json + 对应测试/结果包原始记录（待执行，不代表已经存在）|
|COV-002|M2|独立复现SK-RCE删除，确定exec路径与首次副作用|R2 4/4中的独立一例，受保护内容未删除|docs/research/close-experiment-gaps/m2-verification.json + 对应测试/结果包原始记录（待执行，不代表已经存在）|
|COV-003|M2|独立复现SESSION第一例，冻结可信任务关联|R2/R7；正确关联攻击被防止，错误关联对照正常|docs/research/close-experiment-gaps/m2-verification.json + 对应测试/结果包原始记录（待执行，不代表已经存在）|
|COV-004|M2|独立复现SESSION第二例，不复用未验证根因|R2/R7；跨session副作用及错误关联对照|docs/research/close-experiment-gaps/m2-verification.json + 对应测试/结果包原始记录（待执行，不代表已经存在）|
|SEM-001|M3|运行预指定语义消融，零收益如实报告|开关未参与预览/决策/提交；差异与规则证据一致，不要求制造增益|docs/research/close-experiment-gaps/m3-verification.json + 对应测试/结果包原始记录（待执行，不代表已经存在）|
|EVAL-001|M3|新建机制/来源隔离的20校准+30holdout并冻结|M3全臂、规则/输入/配置hash和一次揭盲记录|docs/research/close-experiment-gaps/m3-verification.json + 对应测试/结果包原始记录（待执行，不代表已经存在）|
|PKG-001|M4|隔离Docker真实安装卸载和block/ask/allow/失联恢复|M4实际注册与副作用收据；不接触日常Gateway|docs/research/close-experiment-gaps/m4-verification.json + 对应测试/结果包原始记录（待执行，不代表已经存在）|
|PKG-002|M4|脱离源码安装wheel后加载SPA静态资源|真实首页及引用资源可达，wheel包含构建产物|docs/research/close-experiment-gaps/m4-verification.json + 对应测试/结果包原始记录（待执行，不代表已经存在）|
|ENG-001|M0|保留已评估办公工具映射，同步两目录并加一致性回归|全部10份JSON一致；三个办公工具在两种加载路径映射一致|docs/research/close-experiment-gaps/m0-verification.json + 对应测试/结果包原始记录（待执行，不代表已经存在）|
|CROSS-001|M2|补充正确关联正例与污染反例、TTL/撤销/重启/幂等|R7，不能仅用全禁用跨会话获得零误报|docs/research/close-experiment-gaps/m2-verification.json + 对应测试/结果包原始记录（待执行，不代表已经存在）|
|BUDGET-001|M1|逐调用归因审批，可信授权复用只限所绑定任务资源|R5产品门及Q5正常总新增≤5分别报告|docs/research/close-experiment-gaps/m1-verification.json + 对应测试/结果包原始记录（待执行，不代表已经存在）|
|PERF-001|M3|原生Hook同入口出口计时并与B0配对|R6绝对p95及Q5配对增量p95≤50ms，原始时间记录|docs/research/close-experiment-gaps/m3-verification.json + 对应测试/结果包原始记录（待执行，不代表已经存在）|
|METHOD-001|M0|将旧离线回放限定设计/校准，不计真实原生分母|报告单列来源与原生等价排除表|docs/research/close-experiment-gaps/m0-verification.json + 对应测试/结果包原始记录（待执行，不代表已经存在）|
|PREC-002|M1|保存v4 N03失败并将其加入可信授权回归|N03真实完成收据，攻击真实无越权副作用|docs/research/close-experiment-gaps/m1-verification.json + 对应测试/结果包原始记录（待执行，不代表已经存在）|
|METHOD-002|M0|保留历史G门，仅用揭盲前固定的新R/Q5作新结论|历史原文件hash不变；新门hash在揭盲前冻结|docs/research/close-experiment-gaps/m0-verification.json + 对应测试/结果包原始记录（待执行，不代表已经存在）|
|PKG-003|M0|保留startupHealthCheck修复，在Docker验证首次注册|JS既有回归+M4原生首次请求进入Guard|docs/research/close-experiment-gaps/m0-verification.json + 对应测试/结果包原始记录（待执行，不代表已经存在）|
|ENG-002|M0|保留测试环境恢复修复，完整回归记录|全量回归无env跨测试污染，不以旧740结果代替未来测试|docs/research/close-experiment-gaps/m0-verification.json + 对应测试/结果包原始记录（待执行，不代表已经存在）|
|DOC-001|M5|同步README/CLAUDE/路线图的严格fail-open描述，AGENTS只读核对|错误和不可解析响应全部透传，旧描述无现行入口残留|docs/research/close-experiment-gaps/m5-verification.json + 对应测试/结果包原始记录（待执行，不代表已经存在）|
|EVAL-002|M3|显式列出Hook之外入口和离线透传边界|边界清单，失败条件不被计为防护；不推断部署覆盖率|docs/research/close-experiment-gaps/m3-verification.json + 对应测试/结果包原始记录（待执行，不代表已经存在）|
|EVAL-003|M3|增加真实自主Agent任务及定向Auth/Cross消融|独立报告是否尝试动作、结果和关闭组件证据|docs/research/close-experiment-gaps/m3-verification.json + 对应测试/结果包原始记录（待执行，不代表已经存在）|
|GATE-001|M0|统一效果判据、零新增正常失败及产品/Q5双门|acceptance.json与spec/任务/计划一致；独立复核冻结|docs/research/close-experiment-gaps/m0-verification.json + 对应测试/结果包原始记录（待执行，不代表已经存在）|
