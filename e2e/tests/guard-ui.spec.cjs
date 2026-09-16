const { test, expect } = require("@playwright/test");
const { getBaseUrl, getHookToken, readServer } = require("./_helpers.cjs");

test.describe("OpenClaw Guard UI", () => {
  test("RV 模式开关可无刷新切换，并控制 Trace 显示", async ({ page }) => {
    const baseUrl = getBaseUrl();
    await page.goto(baseUrl, { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("heading", { name: "龙虾卫士" })).toBeVisible();

    await expect(page.locator(".trace-card")).toBeVisible();

    await page.click("#rv-toggle");
    await expect(page.locator(".trace-card")).toHaveCount(0);
    await expect
      .poll(async () => page.evaluate(() => localStorage.getItem("openclaw-guard-rv-mode")))
      .toBe("off");

    await page.click("#rv-toggle");
    await expect(page.locator(".trace-card")).toBeVisible();
    await expect
      .poll(async () => page.evaluate(() => localStorage.getItem("openclaw-guard-rv-mode")))
      .toBe("on");
  });

  test("Skills 页可启停 skill（走后端 upsert 接口）", async ({ page, request }, testInfo) => {
    const baseUrl = getBaseUrl();
    // Each browser project shares one smoke-test server.  Use a project-local
    // fixture name so parallel browsers cannot race on the same toggle.
    const skillName = `demoSkill-${testInfo.project.name}`;
    const reset = await request.post(new URL("/api/skills/upsert", baseUrl).toString(), {
      data: { name: skillName, enabled: false, description: "E2E demo skill", permissions: ["skill_run"] }
    });
    expect(reset.ok()).toBeTruthy();
    await page.goto(baseUrl, { waitUntil: "domcontentloaded" });
    await page.click('a.nav-btn[href="/skills"]');
    await expect(page.getByRole("heading", { name: "技能管理" })).toBeVisible();

    const btn = page.locator(`button.skill-toggle[data-skill="${skillName}"]`);
    await expect(btn).toBeVisible();
    await expect(btn).toHaveText(/已启用|已停用/);

    const before = await btn.textContent();
    await btn.click();
    await expect(page.locator("#toast-root .toast")).toBeVisible();

    if ((before || "").includes("已启用")) {
      await expect(btn).toHaveText("已停用");
      await expect(btn).toHaveClass(/off/);
    } else {
      await expect(btn).toHaveText("已启用");
      await expect(btn).toHaveClass(/on/);
    }
  });

  test("Hook 动作仅在 OpenClaw 侧审批，Guard 页面只读同步", async ({ page, request }) => {
    const baseUrl = getBaseUrl();

    const response = await request.post(new URL("/api/hook/before-tool-call", baseUrl).toString(), {
      headers: { "x-openclaw-guard-token": getHookToken() },
      data: {
        toolName: "exec",
        params: { command: "rm /Users/dynooob/test.txt" },
        runId: "e2e-run",
        toolCallId: "e2e-call",
        sessionKey: "e2e-session",
        sessionId: "e2e-session",
        agentId: "e2e-agent"
      }
    });
    expect(response.ok()).toBeTruthy();
    const decision = await response.json();
    expect(decision.action).toBe("require_approval");

    await page.goto(baseUrl, { waitUntil: "domcontentloaded" });
    await expect(page.getByRole("heading", { name: "龙虾卫士" })).toBeVisible();

    await expect(page.locator(".trace-card")).toBeVisible();
    await expect(page.locator(".trace-card")).toContainText("总耗时");

    await expect(page.locator(".approve-action")).toHaveCount(0);
    await expect(page.locator(".sync-hint").first()).toContainText("OpenClaw");
  });

  test("Guard 动作页展示意图摘要和脱敏命令详情", async ({ page, request }) => {
    const baseUrl = getBaseUrl();
    const projectDir = readServer().projectDir;
    const response = await request.post(new URL("/api/hook/before-tool-call", baseUrl).toString(), {
      headers: { "x-openclaw-guard-token": getHookToken() },
      data: {
        toolName: "custom_exec",
        params: { command: "echo safe", cwd: projectDir },
        runId: "e2e-summary-run",
        toolCallId: "e2e-summary-call",
        sessionId: "e2e-summary-session",
        agentId: "e2e-summary-agent"
      }
    });
    expect(response.ok()).toBeTruthy();
    const decision = await response.json();
    expect(decision.action).toBe("require_approval");
    expect(decision.approval.intent_summary).toBeTruthy();
    expect(decision.approval.command_preview).toContain("echo safe");

    await page.goto(baseUrl, { waitUntil: "domcontentloaded" });
    await page.click('a.nav-btn[href="/actions"]');
    const card = page.locator('.approval-card').filter({ hasText: "echo safe" }).first();
    await expect(card).toBeVisible();
    await card.locator("details.approval-details").click();
    await expect(card).toContainText("命令与参数");
    await expect(card).toContainText("echo safe");
  });

  test("OpenClaw 回调后 Guard 页面通过 SSE 及时移除待确认动作", async ({ page, request }) => {
    const baseUrl = getBaseUrl();
    const marker = `e2e-live-sync-${Date.now()}`;
    const response = await request.post(new URL("/api/hook/before-tool-call", baseUrl).toString(), {
      headers: { "x-openclaw-guard-token": getHookToken() },
      data: {
        toolName: "custom_exec",
        params: { command: `echo ${marker}`, cwd: readServer().projectDir },
        runId: marker,
        toolCallId: `${marker}-call`,
        sessionId: `${marker}-session`,
        agentId: "e2e-live-agent"
      }
    });
    expect(response.ok()).toBeTruthy();
    const decision = await response.json();
    expect(decision.action).toBe("require_approval");

    await page.goto(baseUrl, { waitUntil: "domcontentloaded" });
    const pendingSection = page.getByRole("heading", { name: /待确认动作/ }).locator("..").locator("..");
    const card = pendingSection.locator(".approval-card").filter({ hasText: marker });
    await expect(card).toBeVisible();

    const resolved = await request.post(new URL("/api/hook/resolve-approval", baseUrl).toString(), {
      headers: { "x-openclaw-guard-token": getHookToken() },
      data: { actionId: decision.action_record.action_id, decision: "allow-once" }
    });
    expect(resolved.ok()).toBeTruthy();

    // The page is subscribed before resolution; this assertion exercises
    // action.resolved → fetchAction → store reconciliation rather than the
    // ten-second polling fallback.
    await expect(card).toHaveCount(0, { timeout: 5_000 });
  });
});
