# M1 认证 Hook 资源引用接入

## 已完成

`HostAuthorizationBridge` 把服务端认证后的 Hook 主体、Agent、session/run，与宿主任务记录和具体工具资源引用关联。提交状态写入唯一真实 `tool-call-v1` 事件的 `context.host_authorization`，不会生成额外调用、修改操作族/效果/标签或改变 PMKB/RV 裁决。

登记契约包括 `read.path`、`office_message_send.sourcePath`、`office_network_post.sourcePath`、`office_document_share.sourcePath/document`；操作族必须符合有限工具映射。其他工具、未知命名空间、缺失认证或无法安全读取的引用不能产生可信授权匹配。资源路径目前要求宿主命名空间内相对路径，未知沙箱路径映射不能猜测。

工具参数中的 task/session/grant ID、附件授权文字、`raw_user_intent`、文件名与 `public` 标签均不签发授权。任务由宿主有效记录解析，错误或歧义关联不复用。

## 引用与内容血缘的区别

输出固定标记 `content_relationship=parameter_reference_only`、`content_lineage_verified=false`。`reference_grant_match=true`只表示当前宿主文件版本与已有授权范围匹配，不能证明实际外发字节来自该文件，也不能表示完整调用获准。

尚需实现真实读取/变换证据与执行时版本检查。尤其工具引用文件后又发送不同body、回调失败/丢失、复制打包或摘要生成，均不能靠引用描述补成可信血缘。现有RV独立block与PMKB硬约束保持。

## 显式启用

默认不加载此功能。可信宿主的配置文件和父目录须分别为私有文件、目录（例如 `0600`/`0700`），位于所有Agent工作区之外。

```json
{
  "state_dir": "/srv/rvguard-q5/host-authority",
  "agent_workspaces": ["/srv/rvguard-q5/workspace"],
  "namespaces": {"office": "/srv/rvguard-q5/workspace"},
  "tool_namespaces": {
    "read": "office",
    "office_message_send": "office",
    "office_network_post": "office",
    "office_document_share": "office"
  }
}
```

启动隔离实例：

```sh
python -m openclaw_guard.main run \
  --project-dir /srv/rvguard-q5/project --profile rvguard-q5 \
  --host-authorization-config /srv/rvguard-q5/host-authority/config.json
```

配置中的路径仅为示例，不会自动创建实验环境或修改日常Gateway。Docker不挂载授权目录及限制宿主exec仍需独立验收。

## 消融与验证

Auth关闭时，宿主授权查询、任务解析、资源观察和证据写入均不参与。引用证据尚未用于决策，因此不能用本轮测试宣称该组件已经改善防护或审批。

本轮仅执行 bridge+有限工具模型定向测试：51项通过（3.56秒）；补充操作族/命名空间反例后，bridge模块9项通过（0.24秒）。未跑全量回归、未重跑真实实验。M0冻结文件哈希无变化，DSL规则与既有实验manifest一致。M1仍未验收。

## 热路径修正

独立复核发现同步读取与SQLite等待可能超过插件2秒默认超时，从而间接触发fail-open。本轮已移除同步观察：before Hook只向16容量的队列非阻塞提交，单个后台daemon读取资源和授权，结果保存在最多64项诊断缓存，不回填先前裁决。队列满返回不确定，默认裁决照常；配置关闭和服务退出停止接收任务，不等待慢IO。后台结果可通过`reference_evidence(event_id)`查询，仅供后续诊断。

修正后bridge11项0.30秒通过，含慢worker未完成时提交及时返回、队列满不等待及RV仍立即独立block。Hook bearer认证不等于Agent/session/run已独立绑定；这些字段目前源自SDK上下文，后续用于放行前须验证宿主来源与每Agent作用域。M1仍未通过。
