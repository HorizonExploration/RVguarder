# M1 已执行内容证据与版本契约

## 已实现的边界

`spec/content_receipts.py` 使用宿主私有 HMAC 密钥签发受控执行器收据，绑定任务、认证主体、Agent、session/run/call、具体工具及有限操作族、原参数哈希、实际消费或产生的内容版本与五分钟期限。签发和核验均重新核对宿主唯一活动任务，合法签名也不能关联到错误、撤销或歧义任务。

签发器不是 Agent 工具，也没有 HTTP 签发入口。收据不签发授权，不证明 `public` 分类。只有实际成功且效果符合 `tool-call-v1` 的调用可入表；失败、未知效果、伪造、过期、冲突均不能建立关系。重复提交幂等，容量满不静默覆盖旧证据。

after Hook 在既有成功历史提交后，仅向后台核验队列提交有界冻结副本。数据库校验在后台进行，缺失、超限、关闭或无效证据不改变原裁决或成功历史。Auth 消融同时关闭提交和核验路径。默认没有配置收据表，既有行为保持。

## 工具实际处理的字节

`testlab/office_chain/native_office_plugin/index.js` 的三个既有办公工具增加默认关闭的宿主配置 `executionEvidence`。签名所用 Buffer 与本地合成副作用收据的 Buffer 相同，文件优先于 body；工具自报任务/身份不用于签发。SDK 上下文缺失或歧义时仍执行原工具，但不签发内容证据。

配置须在可信执行器一侧。密钥不能进入 Agent 可读的容器、任意宿主 exec 或可写插件配置；同 UID 的文件私有权限本身不能保证这一点。签发器配置不随产品候选包分发。

三个工具还支持可选 `expectedSourceSha256`。检查实际消费的同一 Buffer，发生在第一条副作用 JSONL 写入之前；文件不存在时不能退回 body。该参数可以省略，也可由调用者填写，**本身不是授权**。后续受控放行必须强制核对它与宿主授权版本及执行器契约，不能据此宣布通用 TOCTOU 已解决。

## 内容关系组合

`spec/content_flow.py` 只查询已核验收据表。复制和变换按命名空间、资源 ID、哈希、大小与完整读取范围连接，要求同一活动宿主任务、主体、Agent、session 和确切 run。它能组合未预置名称的复制→变换→复制路径，见证始终是已有的真实 run/call，没有额外工具事件。

变换关系表示输入参与调用，**不证明输出包含秘密，也不把摘要降级为公开**。关系查询包含宿主 IO，只供后台分析；目前不进入 PMKB/RV 决策。TTL、撤销和错误身份不会复用关系；持久恢复、跨 run/session 复用仍待 M2。

## 验证及范围

- 内容收据基础：20 项定向测试，包括合法错任务签名、撤销/歧义、异步对象突变及超大/深 JSON 处理量限制。
- Node→Python：三个实际办公工具执行字节与签名互通；缺失/歧义上下文、密钥父目录软链接、执行前后换内容及缺失文件反例，共 9 项。既有 Node 工具测试 6 项通过。
- 内容关系查询：9 项，包括未命名组合、同名换版本、命名空间/身份隔离、TTL、撤销、循环。
- [实际安装 SDK 契约](m1-local-sdk-contract.json)：OpenClaw 2026.9.5 派发器保留 details、失败标记和上下文，正确传递 allow/block；HTTP 为 mock，无 Agent 或原生审批。
- [Docker 挂载边界](m1-docker-key-isolation.json)：7 项通过，只使用公开固定零字节 fixture，未生成或暴露签名密钥。

复验命令：

```sh
python -m pytest tests/test_content_receipts.py tests/test_content_flow.py tests/test_native_content_receipts.py -q
node --test testlab/office_chain/native_office_plugin/index.test.mjs
python -m scripts.check_local_sdk_hook_contract --output /tmp/rv-sdk-contract.json
python -m scripts.check_content_key_isolation --output /tmp/rv-mount-contract.json
```

这些是基础组件与契约检查，不加入安全实验分母。尚缺实际 OpenClaw 部署隔离、原生 read/write 的可信生产适配、授权裁决接入、公开摘要和 v4 N03 的真实完成收据。**M1 未通过，未启动 M3 新盲测，未发布。**
