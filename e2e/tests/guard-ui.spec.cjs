const { test, expect } = require("@playwright/test");
const { getBaseUrl, getHookToken } = require("./_helpers.cjs");

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

  test("Skills 页可启停 skill（走后端 upsert 接口）", async ({ page }) => {
    const baseUrl = getBaseUrl();
    await page.goto(baseUrl, { waitUntil: "domcontentloaded" });
    await page.click('a.nav-btn[href="/skills"]');
    await expect(page.getByRole("heading", { name: "技能管理" })).toBeVisible();

    const btn = page.locator('button.skill-toggle[data-skill="demoSkill"]');
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
});
