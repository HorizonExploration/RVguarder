# E2E（Playwright）

本目录用于端到端回归测试：启动 `openclaw-guard` 后，通过浏览器自动化验证 RV 模式开关、Trace 展示、Skills 启停与动作审批等关键链路。

## 运行方式

在仓库根目录执行：

```bash
cd e2e
npm install
npm run install:browsers
npm test
```

如果运行环境注入了 HTTP(S) 代理，Firefox 可能出现 `NS_ERROR_NET_ERROR_RESPONSE`；可在本地串行复跑：

```bash
env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY -u http_proxy -u https_proxy -u all_proxy \
  npx playwright test tests/guard-ui.spec.cjs --project=firefox --workers=1
```

## 覆盖点

- RV 模式开关：无刷新切换，Trace 区域随开关显隐（localStorage 持久化）
- Skills 管理：对 `demoSkill` 执行启用/停用（调用 `/api/skills/upsert`）
- 审批链路：注入一个 `pending_approval` 动作，通过 OpenClaw resolution callback 完成审批；Guard 页面只读观察并验证 SSE 同步

## 说明

- 测试会在启动时自动创建临时 `projectDir` 与最小 `openclaw.json`，并用 `python -m openclaw_guard.main run` 拉起服务（端口随机）。
- 结束测试时会自动关闭服务并清理临时目录。
