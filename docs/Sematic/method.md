根据目前项目情况和测试检测的结果,对目前输入的匹配规则进行下列修改优化尝试:
1.首先找出检测匹配筛选规则全链路对应的文件
2.考虑增加语义理解功能方案3：轻量级 LLM API + 结构化输出
  使用返回速度最快的 LLM API(最好是deepseek模型)
  通过精心设计的 prompt 和结构化输出来实现全量覆盖。

BehaviorEvent
    │
    ├── DetectionEngine.evaluate()  ← 现有 47 条规则（不变）
    │       │
    │       └── 命中规则 → 直接返回决策（0.01s）
    │
    └── 未命中规则时 → SemanticEnhancer.evaluate()
            │
            ├── 本地快速过滤
            │   └── 简单的"攻击关键词"检查作为前置过滤
            │
            ├── LLM API 调用（200-400ms）
            │   └── 返回结构化 JSON: intent + risk + confidence
            │
            └── 决策融合
                ├── 高置信度攻击 → block
                ├── 中置信度 → ask
                └── 低置信度 → 走原有 Fallback

目前整体方案设计：用户给出输入后，
        进行基于规则化LLM输出的语义理解后并分解成指令形成trace，之后对这些指令进行风险检测
        进行Back-translation 验证 将 Trace 反向翻译为 NL：
         "查找 /tmp 下的.cache文件，然后删除这些文件" 与原始输入对比：原始: "清理 tmp 下7天前的缓存"          重建: "查找并删除.cache文件" → 不一致！缺少 "7天前" 约束 → 触发精炼，补全遗漏条件
        参考: ProSA 的 Back-translation 验证机制  
 基于trace上下文感知风险检测   
上下文感知风险检测 
├─ 3A: 单条指令规则检测 (原有)                   
│    DetectionEngine → 47 条规则匹配              ← 单事件判决
  用户自定义规则
│
├─ 3B: 链式风险检测 (RV 引擎)              
│    RuntimeVerificationEngine                    ← 跨步骤检测
│    ├─ 时态逻辑公式 DSL（用户可自定义）
│    ├─ 滑动窗口模型检查
│    └─ 内置不变量库 + 用户自定义不变量（从用户定义规则提取）
│
├─ 3C: 意图-命令对齐检测                        ← 语义层
│    IntentCommandAlignment (LLM, 高风险时触发)
│
├─ 3D: 解域验证                                     ← 约束层
│    SolutionDomainValidator
│
└─ 3E: RV 反馈驱动
     当 RV 检测到违规 → 提取违规窗口 → 反馈给 DetectionEngine
     → 自动生成/补全缺失的规则
