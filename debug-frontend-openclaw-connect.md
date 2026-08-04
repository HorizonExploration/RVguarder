#[OPEN] Debug Session: frontend-openclaw-connect

## 症状
- 现象：前端重构后无法正常连接到 OpenClaw（WebSocket 连接失败 / 一直显示未连接）
- 期望：前端能通过配置的 ws 地址 + token 与 OpenClaw Gateway 建立连接，并正常展示状态与数据

## 复现步骤（待补充）
1.

## 运行环境（待补充）
- OS: linux
- Browser:
- OpenClaw 版本:
- Gateway 地址/端口:
- Guarder 前端地址/端口:

## 假设（待证伪）
1. 前端重构后 WebSocket URL 组装错误（ws/wss、路径、query 参数 token），导致握手失败
2. token 获取/存储逻辑变更，前端实际发送的是空 token 或旧 token，导致 401/close
3. 连接时机或状态机问题：页面刷新后连接逻辑未触发、被某个条件短路、或被异常吞掉
4. 后端代理/网关地址来源变更（env/config），前端连接到了错误的 host/port（例如默认 127.0.0.1:18789 与实际不一致）
5. CORS/WS 代理配置问题：Vite dev server 代理或生产静态托管未透传 WS upgrade

## 证据采集计划
- A. 抓取前端网络请求与 WebSocket close code/close reason
- B. 打印（通过调试上报）前端最终计算出的 wsUrl、token 长度、连接状态迁移路径
- C. 对照 OpenClaw Gateway 日志与状态接口，确认服务端是否收到连接/拒绝原因

## 变更记录
- 尚未开始插桩与修复

