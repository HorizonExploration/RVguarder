from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def build_ui(target_dir: Path, summary: dict[str, Any]) -> None:
    target_dir.mkdir(parents=True, exist_ok=True)
    (target_dir / "index.html").write_text(_index_html(summary), encoding="utf-8")
    (target_dir / "app.js").write_text(_app_js(), encoding="utf-8")
    (target_dir / "styles.css").write_text(_styles(), encoding="utf-8")


def _index_html(summary: dict[str, Any]) -> str:
    return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Openclaw Guard | 龙虾卫士</title>
  <link rel="stylesheet" href="/styles.css">
</head>
<body>
  <div id="app"></div>
  <script>window.__OPENCLAW_GUARD_SUMMARY__ = {json.dumps(summary, ensure_ascii=False)};</script>
  <script src="/app.js"></script>
</body>
</html>"""


def _app_js() -> str:
    return r"""const state = {
  summary: window.__OPENCLAW_GUARD_SUMMARY__ || {},
  conversation: (window.__OPENCLAW_GUARD_SUMMARY__ || {}).console || { messages: [], pending_requests: [] },
  chatStatus: (window.__OPENCLAW_GUARD_SUMMARY__ || {}).chat || {},
  view: "chat",
  lang: localStorage.getItem("openclaw-guard-lang") || "zh",
  draft: "",
  sending: false,
  awaitingReplyActionId: null,
  actionFilter: "pending_approval",
  pages: {
    actions: 1,
    skills: 1,
    channels: 1,
  },
  pageSize: 6,
  toast: null,
  scan: {
    running: false,
    progress: 0,
    phase: "",
    result: null,
    selected: "config",
  },
  runtimeDebug: null,
  debugLogs: [],
  actionWatchingId: null,
};

const I18N = {
  zh: {
    appName: "龙虾卫士",
    appSub: "安全增强版 OpenClaw 工作台",
    chat: "对话",
    actions: "动作",
    skills: "技能",
    channels: "渠道",
    settings: "设置",
    connected: "已连接",
    detected: "已检测",
    disconnected: "未连接",
    auth_required: "需要鉴权",
    unavailable: "不可用",
    refresh: "刷新",
    newChat: "新对话",
    send: "发送",
    sending: "发送中...",
    thinking: "正在等待回复...",
    onlineHint: "你现在可以直接和 OpenClaw 对话，危险动作会在执行前先停下来等你确认。",
    offlineHint: "当前无法连接到 OpenClaw 运行时，请先启动 OpenClaw gateway。",
    inputPlaceholder: "直接输入你的问题或任务，例如：请帮我检查最近的日志",
    pendingTitle: "待确认动作",
    pendingInlineTitle: "这条请求已暂停，等待你确认",
    noPending: "当前没有待确认动作。",
    recentActions: "最近动作",
    noActions: "还没有动作记录。",
    runtime: "运行状态",
    workspace: "工作区",
    profile: "Profile",
    model: "模型",
    agent: "Agent",
    unknown: "未识别",
    pendingApproval: "待确认",
    blocked: "已拦截",
    executed: "已执行",
    failed: "失败",
    approve: "确认继续",
    reject: "拒绝",
    details: "查看详情",
    riskSafe: "低风险",
    riskCaution: "需留意",
    riskDangerous: "高风险",
    riskBlocked: "已阻断",
    actionReason: "原因",
    openActions: "打开动作页",
    securitySettings: "安全中心与高级设置",
    baseline: "基线扫描",
    audit: "审计导出",
    capabilities: "采集能力",
    noMessages: "开始一次对话吧。",
    assistant: "助手",
    user: "你",
    system: "系统",
    changeModel: "切换模型",
    modelSwitchFailed: "模型切换失败，请稍后重试。",
    confirmWord: "确认词",
    needSecondConfirm: "这个动作还需要输入确认词后才能继续。",
    status_pending_approval: "待确认",
    status_blocked: "已拦截",
    status_executed: "已执行",
    status_failed: "失败",
    status_executing: "执行中",
    status_approved: "已批准",
    status_rejected: "已拒绝",
    status_proposed: "已提出",
    actionType_chat_message: "对话消息",
    actionType_command_exec: "命令执行",
    actionType_file_delete: "删除文件",
    actionType_file_write: "写入文件",
    actionType_config_modify: "修改配置",
    actionType_network_egress: "外部联网",
    actionType_channel_send: "渠道发送",
    actionType_skill_run: "运行技能",
    error_message_empty: "消息内容不能为空。",
    error_cli_not_found: "没有找到 OpenClaw 入口，请先确认 OpenClaw 已正确安装。",
    error_config_not_found: "没有找到 OpenClaw 配置，请检查 openclaw.json 或当前 profile。",
    error_gateway_unreachable: "当前无法连接到 OpenClaw 运行时，请先启动 OpenClaw gateway。",
    error_gateway_auth_failed: "已经连到 OpenClaw gateway，但鉴权没有通过，请检查 token 或 password。",
    error_runtime_not_running: "当前无法确认 OpenClaw 正在运行，请先检查 gateway 状态。",
    error_send_failed: "消息发送失败，请稍后重试。",
    error_wait_timeout: "消息已经发出，但等待回复超时了，请稍后重试。",
    error_history_fetch_failed: "消息已发送，但暂时拿不到会话记录，请稍后刷新。",
    error_reply_not_found: "消息已发送，但暂时没有拿到回复内容。",
    error_gateway_call_failed: "OpenClaw 调用失败，请检查 gateway 是否正常运行。",
    error_gateway_invalid_response: "OpenClaw 返回了无法解析的响应。",
    error_plugin_load_failed: "Guard Hook 插件没有被 OpenClaw 正常加载，请检查插件语法并重启 gateway。",
    error_runtime_hook_inactive: "Guard Hook 当前未连接到 OpenClaw 真实执行链，危险动作不会继续执行。",
    error_provider_rate_limited: "当前模型服务已限流或额度不足，请稍后重试，或切换到其他可用模型。",
    error_provider_auth_failed: "当前模型服务鉴权失败，请检查模型配置。",
    error_runtime_execution_failed: "本次回复执行失败，请查看日志后重试。",
    error_action_blocked: "这个动作风险过高，已被龙虾卫士拦截。",
    error_action_confirmation_required: "这个动作需要你先确认，确认前不会继续执行。",
    error_action_not_found: "未找到对应动作记录。",
    error_action_not_pending: "该动作当前不在待审批状态。",
    error_action_not_ready: "该动作当前不能执行。",
    error_confirmation_word_required: "缺少正确的二次确认词。",
    error_default: "请求处理失败，请稍后重试。",
    skillsEmpty: "这里会显示当前 OpenClaw 可用的技能和风险标签。",
    channelsEmpty: "这里会显示当前可连接渠道、状态和最近活动。",
    settingsHint: "专业扫描、审计和导出入口都放在这里，不会打断你的日常对话。",
    save: "保存",
    delete: "删除",
    enabled: "启用",
    disabled: "停用",
    target: "目标",
    description: "说明",
    permissions: "权限",
    addSkill: "添加技能",
    addChannel: "添加渠道",
    guardMode: "防护模式",
    strict: "严格",
    balanced: "平衡",
    replyScan: "回复扫描",
    saved: "已保存",
    prevPage: "上一页",
    nextPage: "下一页",
    pageInfo: "第 {current} / {total} 页",
    noItems: "当前没有内容。",
    footerDisclaimer: "AI助手无法保证准确性",
    footerCopyright: "© 2026 By DyNooob",
    scanTitle: "基线扫描",
    scanIdle: "准备开始基线扫描",
    scanHint: "会检查配置、端口、依赖、运行用户和审计项。为了让结果更清晰，这里会保留一个短暂的扫描过场。",
    scanRunning: "正在扫描中…",
    scanFinished: "扫描完成",
    scanStart: "开始扫描",
    scanProgress: "当前阶段",
    scanStage_prepare: "准备扫描环境",
    scanStage_config: "检查配置与权限",
    scanStage_runtime: "核对运行状态与开放端口",
    scanStage_audit: "整理报告与整改建议",
    scanCategory_config: "配置与权限",
    scanCategory_runtime: "运行环境",
    scanCategory_dependency: "依赖与源代码",
    scanCategory_audit: "审计与资产",
    scanIssues: "问题",
    scanAssets: "资产",
    scanChecks: "检查项",
    scanDetails: "详细说明",
    scanStatus_ok: "正常",
    scanStatus_warn: "需留意",
    scanStatus_risk: "存在风险",
    solution: "解决方案",
    showSolution: "查看方案",
    hookTitle: "运行时拦截状态",
    hookActive: "已接入 OpenClaw 工具拦截链",
    hookInactive: "还没有接入 OpenClaw 工具拦截链",
    hookRestart: "需要重启 OpenClaw gateway 后才会生效。",
    hookConfigFailed: "当前没有权限写入 OpenClaw 配置，所以运行时 Hook 还没真正启用。",
    hookLoadedWaitingRestart: "插件已加载，等待当前 gateway 重启后接入。",
    hookRuntimeUnreachable: "当前运行时不可达，暂时无法确认 Hook 是否在线。",
    hookRuntimeCommand: "建议命令",
    hookPluginLoaded: "插件已加载",
    hookPluginInvalid: "插件异常",
    hookRuntimeStatus: "运行时状态",
    runtimeRefresh: "刷新运行时",
    runtimeDebug: "运行时调试",
    recentLogs: "最近日志",
    loadDebug: "加载调试信息",
    reloadLogs: "刷新日志",
    debugEmpty: "这里会显示运行时状态、Hook 状态和最近日志。",
  },
  en: {
    appName: "Openclaw Guard",
    appSub: "A safer OpenClaw workspace",
    chat: "Chat",
    actions: "Actions",
    skills: "Skills",
    channels: "Channels",
    settings: "Settings",
    connected: "Connected",
    detected: "Detected",
    disconnected: "Offline",
    auth_required: "Auth required",
    unavailable: "Unavailable",
    refresh: "Refresh",
    newChat: "New chat",
    send: "Send",
    sending: "Sending...",
    thinking: "Waiting for reply...",
    onlineHint: "You can chat with OpenClaw here. Risky actions will pause first and wait for your approval.",
    offlineHint: "Cannot reach the OpenClaw runtime. Please start the OpenClaw gateway first.",
    inputPlaceholder: "Type a question or task, for example: help me inspect the latest logs",
    pendingTitle: "Pending approvals",
    pendingInlineTitle: "This request is paused and waiting for your approval",
    noPending: "No pending approvals right now.",
    recentActions: "Recent actions",
    noActions: "No action records yet.",
    runtime: "Runtime",
    workspace: "Workspace",
    profile: "Profile",
    model: "Model",
    agent: "Agent",
    unknown: "Unknown",
    pendingApproval: "Pending",
    blocked: "Blocked",
    executed: "Executed",
    failed: "Failed",
    approve: "Approve",
    reject: "Reject",
    details: "View details",
    riskSafe: "Low risk",
    riskCaution: "Caution",
    riskDangerous: "High risk",
    riskBlocked: "Blocked",
    actionReason: "Reason",
    openActions: "Open actions",
    securitySettings: "Security center and advanced settings",
    baseline: "Baseline scan",
    audit: "Audit export",
    capabilities: "Collectors",
    noMessages: "Start a conversation.",
    assistant: "Assistant",
    user: "You",
    system: "System",
    changeModel: "Switch model",
    modelSwitchFailed: "Model switch failed. Please try again.",
    confirmWord: "Confirm word",
    needSecondConfirm: "This action still needs a confirmation word before it can continue.",
    status_pending_approval: "Pending",
    status_blocked: "Blocked",
    status_executed: "Executed",
    status_failed: "Failed",
    status_executing: "Running",
    status_approved: "Approved",
    status_rejected: "Rejected",
    status_proposed: "Proposed",
    actionType_chat_message: "Chat message",
    actionType_command_exec: "Command execution",
    actionType_file_delete: "File delete",
    actionType_file_write: "File write",
    actionType_config_modify: "Config change",
    actionType_network_egress: "Network egress",
    actionType_channel_send: "Channel send",
    actionType_skill_run: "Skill run",
    error_message_empty: "Message text cannot be empty.",
    error_cli_not_found: "No OpenClaw entry point was found. Please verify that OpenClaw is installed.",
    error_config_not_found: "OpenClaw config was not found. Check the openclaw.json path or the current profile.",
    error_gateway_unreachable: "Cannot reach the OpenClaw runtime. Please start the OpenClaw gateway first.",
    error_gateway_auth_failed: "The OpenClaw gateway responded, but authentication failed. Check the token or password.",
    error_runtime_not_running: "The OpenClaw runtime could not be confirmed. Please check the gateway state.",
    error_send_failed: "The message could not be sent. Please try again.",
    error_wait_timeout: "The message was sent, but waiting for a reply timed out. Please try again.",
    error_history_fetch_failed: "The message was sent, but chat history is not available yet. Please refresh.",
    error_reply_not_found: "The message was sent, but no reply was found yet.",
    error_gateway_call_failed: "OpenClaw call failed. Please verify that the gateway is healthy.",
    error_gateway_invalid_response: "OpenClaw returned an unreadable response.",
    error_plugin_load_failed: "The Guard Hook plugin did not load correctly. Check the plugin syntax and restart the gateway.",
    error_runtime_hook_inactive: "The Guard Hook is not connected to the real OpenClaw execution chain, so risky actions will not continue.",
    error_provider_rate_limited: "The selected model is rate limited or out of quota. Try again later or switch to another model.",
    error_provider_auth_failed: "Model provider authentication failed. Please review the model configuration.",
    error_runtime_execution_failed: "This reply failed during execution. Please check logs and try again.",
    error_action_blocked: "This action was blocked because the risk is too high.",
    error_action_confirmation_required: "This action needs your approval before it can continue.",
    error_action_not_found: "The requested action record was not found.",
    error_action_not_pending: "This action is no longer pending approval.",
    error_action_not_ready: "This action cannot run in its current state.",
    error_confirmation_word_required: "A valid confirmation word is still required.",
    error_default: "The request failed. Please try again.",
    skillsEmpty: "This panel will show available skills and their risk labels.",
    channelsEmpty: "This panel will show connected channels, status, and recent activity.",
    settingsHint: "Professional scans, audit exports, and advanced controls live here so they do not overwhelm the chat view.",
    save: "Save",
    delete: "Delete",
    enabled: "Enabled",
    disabled: "Disabled",
    target: "Target",
    description: "Description",
    permissions: "Permissions",
    addSkill: "Add skill",
    addChannel: "Add channel",
    guardMode: "Guard mode",
    strict: "Strict",
    balanced: "Balanced",
    replyScan: "Reply scan",
    saved: "Saved",
    prevPage: "Previous",
    nextPage: "Next",
    pageInfo: "Page {current} / {total}",
    noItems: "Nothing here yet.",
    footerDisclaimer: "AI assistant responses may be inaccurate",
    footerCopyright: "© 2026 By DyNooob",
    scanTitle: "Baseline scan",
    scanIdle: "Ready to start a baseline scan",
    scanHint: "The scan checks config, ports, dependencies, runtime user, and audit settings. A short animated pass keeps the process readable.",
    scanRunning: "Scanning…",
    scanFinished: "Scan finished",
    scanStart: "Start scan",
    scanProgress: "Current stage",
    scanStage_prepare: "Preparing the environment",
    scanStage_config: "Checking config and permissions",
    scanStage_runtime: "Inspecting runtime and open ports",
    scanStage_audit: "Building report and remediation advice",
    scanCategory_config: "Config & permissions",
    scanCategory_runtime: "Runtime",
    scanCategory_dependency: "Dependencies",
    scanCategory_audit: "Audit & assets",
    scanIssues: "Issues",
    scanAssets: "Assets",
    scanChecks: "Checks",
    scanDetails: "Details",
    scanStatus_ok: "Healthy",
    scanStatus_warn: "Needs attention",
    scanStatus_risk: "Risk found",
    solution: "Solution",
    showSolution: "Show fix",
    hookTitle: "Runtime interception",
    hookActive: "Connected to the OpenClaw tool interception chain",
    hookInactive: "Not connected to the OpenClaw tool interception chain yet",
    hookRestart: "Restart the OpenClaw gateway to activate it.",
    hookConfigFailed: "OpenClaw config could not be written, so the runtime hook is not active yet.",
    hookLoadedWaitingRestart: "Plugin is loaded and waiting for the current gateway process to restart.",
    hookRuntimeUnreachable: "The runtime is currently unreachable, so Hook activity cannot be confirmed yet.",
    hookRuntimeCommand: "Suggested command",
    hookPluginLoaded: "Plugin loaded",
    hookPluginInvalid: "Plugin invalid",
    hookRuntimeStatus: "Runtime status",
    runtimeRefresh: "Refresh runtime",
    runtimeDebug: "Runtime debug",
    recentLogs: "Recent logs",
    loadDebug: "Load debug info",
    reloadLogs: "Reload logs",
    debugEmpty: "Runtime status, Hook status, and recent logs will appear here.",
  },
};

function t(key) {
  return (I18N[state.lang] || I18N.zh)[key] || key;
}

function tf(key, vars = {}) {
  let template = t(key);
  Object.entries(vars).forEach(([name, value]) => {
    template = template.replace(`{${name}}`, String(value));
  });
  return template;
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

async function api(path, options = {}) {
  const response = await fetch(path, options);
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = new Error(payload.error_code || payload.error || "request_failed");
    error.payload = payload;
    throw error;
  }
  return payload;
}

function toast(message) {
  state.toast = message;
  patchToastDom();
  window.clearTimeout(window.__guardToastTimer);
  window.__guardToastTimer = window.setTimeout(() => {
    state.toast = null;
    patchToastDom();
  }, 2800);
}

function errorMessage(payload) {
  const code = payload?.error_code;
  if (code && t(`error_${code}`) !== `error_${code}`) return t(`error_${code}`);
  return payload?.message || t("error_default");
}

function connectionTone() {
  const value = state.chatStatus.connection_state || "disconnected";
  if (value === "connected") return { label: t("connected"), tone: "connected" };
  if (value === "detected") return { label: t("detected"), tone: "detected" };
  if (value === "auth_required") return { label: t("auth_required"), tone: "warning" };
  if (value === "unavailable") return { label: t("unavailable"), tone: "danger" };
  return { label: t("disconnected"), tone: "danger" };
}

function riskLabel(level) {
  const map = {
    safe: t("riskSafe"),
    caution: t("riskCaution"),
    dangerous: t("riskDangerous"),
    blocked: t("riskBlocked"),
  };
  return map[level] || level || t("riskSafe");
}

function actionTitle(item) {
  const event = item.event || {};
  const summary = item.target_summary || "";
  const rawIntent = event.raw_payload?.raw_user_intent || item.source_message || "";
  const label = actionTypeLabel(event.action_type || "");
  if (summary && summary !== "未解析到目标" && summary !== "request") return `${label} · ${summary}`;
  if (rawIntent) return `${label} · ${rawIntent}`;
  return label;
}

function scanCards() {
  const baseline = state.scan.result || state.summary.baseline || {};
  const checks = (baseline.checks && baseline.checks.length) ? baseline.checks : synthesizeChecksFromLegacyBaseline(baseline);
  const assets = baseline.assets || [];
  const groups = {
    config: {
      key: "config",
      title: t("scanCategory_config"),
      checks: checks.filter((item) => item.category === "config"),
      assets: assets.filter((item) => item.category === "openclaw"),
    },
    runtime: {
      key: "runtime",
      title: t("scanCategory_runtime"),
      checks: checks.filter((item) => ["runtime", "network", "os"].includes(item.category)),
      assets: assets.filter((item) => ["system", "network"].includes(item.category)),
    },
    dependency: {
      key: "dependency",
      title: t("scanCategory_dependency"),
      checks: checks.filter((item) => item.category === "dependency"),
      assets: [],
    },
    audit: {
      key: "audit",
      title: t("scanCategory_audit"),
      checks,
      assets,
    },
  };
  return Object.values(groups).map((group) => {
    const severities = group.checks.map((item) => item.severity);
    const hasRisk = group.checks.some((item) => item.status === "risk");
    const hasWarn = group.checks.some((item) => item.status === "warn");
    const tone = hasRisk || severities.includes("critical") || severities.includes("high")
      ? "risk"
      : hasWarn || severities.includes("medium") || severities.includes("low")
        ? "warn"
        : "ok";
    return {
      ...group,
      tone,
      count: group.checks.filter((item) => item.status !== "ok").length,
      totalChecks: group.checks.length,
      statusLabel: tone === "risk" ? t("scanStatus_risk") : tone === "warn" ? t("scanStatus_warn") : t("scanStatus_ok"),
    };
  });
}

function synthesizeChecksFromLegacyBaseline(baseline) {
  const findings = baseline.findings || [];
  if (!findings.length) {
    return [{
      check_id: "legacy-ok",
      category: "audit",
      title: t("scanFinished"),
      status: "ok",
      severity: "info",
      description: t("scanHint"),
      recommendation: t("scanHint"),
      evidence: {},
    }];
  }
  return findings.map((item, index) => ({
    check_id: item.finding_id || `legacy-${index}`,
    category: item.category || "audit",
    title: item.title || t("scanDetails"),
    status: item.severity === "critical" || item.severity === "high" ? "risk" : "warn",
    severity: item.severity || "medium",
    description: item.description || "",
    recommendation: item.recommendation || "",
    evidence: item.evidence || {},
  }));
}

function selectedScanCard() {
  const cards = scanCards();
  return cards.find((item) => item.key === state.scan.selected) || cards[0];
}

function scanProgressValue(card, scanProgress) {
  if (!card) return 100;
  if (!card.totalChecks) return 100;
  if (card.count) return Math.min(100, 34 + card.count * 14);
  if (state.scan.running && state.scan.selected === card.key) return scanProgress;
  return 100;
}

function statusLabel(status) {
  return t(`status_${status}`) !== `status_${status}` ? t(`status_${status}`) : status;
}

function actionTypeLabel(type) {
  return t(`actionType_${type}`) !== `actionType_${type}` ? t(`actionType_${type}`) : type;
}

function paginate(items, pageKey, pageSize = state.pageSize) {
  const total = Math.max(1, Math.ceil(items.length / pageSize));
  const current = Math.min(Math.max(state.pages[pageKey] || 1, 1), total);
  state.pages[pageKey] = current;
  const start = (current - 1) * pageSize;
  return {
    items: items.slice(start, start + pageSize),
    current,
    total,
  };
}

function renderPager(pageKey, current, total) {
  if (total <= 1) return "";
  return `
    <div class="pager">
      <button class="pager-btn" data-page-key="${escapeHtml(pageKey)}" data-page-next="0" ${current <= 1 ? "disabled" : ""}>${escapeHtml(t("prevPage"))}</button>
      <span class="pager-info">${escapeHtml(tf("pageInfo", { current, total }))}</span>
      <button class="pager-btn" data-page-key="${escapeHtml(pageKey)}" data-page-next="1" ${current >= total ? "disabled" : ""}>${escapeHtml(t("nextPage"))}</button>
    </div>
  `;
}

function renderFooter() {
  return `
    <footer class="page-footer">
      <div class="footer-center">${escapeHtml(t("footerDisclaimer"))}</div>
      <div class="footer-right">${escapeHtml(t("footerCopyright"))}</div>
    </footer>
  `;
}

function renderRuntimeDebugPanel() {
  const debug = state.runtimeDebug;
  const logs = state.debugLogs || [];
  if (!debug && !logs.length) {
    return `<div class="placeholder-card compact">${escapeHtml(t("debugEmpty"))}</div>`;
  }
  return `
    <div class="debug-grid">
      ${debug ? `
        <article class="debug-card">
          <div class="side-head"><h3>${escapeHtml(t("runtimeDebug"))}</h3></div>
          <div class="runtime-list dense">
            <div><span>${escapeHtml(t("profile"))}</span><strong>${escapeHtml(debug.profile || t("unknown"))}</strong></div>
            <div><span>Config</span><strong>${escapeHtml(debug.config_path || "—")}</strong></div>
            <div><span>Gateway</span><strong>${escapeHtml((debug.gateway_urls || []).join(" | ") || "—")}</strong></div>
            <div><span>Auth</span><strong>${escapeHtml(debug.auth_mode || "—")}</strong></div>
            <div><span>Relay</span><strong>${escapeHtml(debug.relay?.connection_state || "—")}</strong></div>
            <div><span>Hook</span><strong>${escapeHtml(debug.hook?.state || "—")}</strong></div>
          </div>
        </article>
      ` : ""}
      <article class="debug-card">
        <div class="side-head"><h3>${escapeHtml(t("recentLogs"))}</h3></div>
        <div class="debug-log-list">
          ${logs.length ? logs.slice(-12).reverse().map((item) => `
            <div class="debug-log-item">
              <strong>${escapeHtml(item.event || "log")}</strong>
              <span>${escapeHtml(item.timestamp || "")}</span>
            </div>
          `).join("") : `<div class="placeholder-card compact">${escapeHtml(t("noItems"))}</div>`}
        </div>
      </article>
    </div>
  `;
}

function renderSkillsListSection() {
  const items = (state.summary.skills || {}).items || [];
  const page = paginate(items, "skills");
  return `
      <div class="card-list">
        ${page.items.length ? page.items.map((item) => `
          <article class="config-card">
            <div class="side-head">
              <h4>${escapeHtml(item.name)}</h4>
              <span class="status-chip">${escapeHtml(item.enabled ? t("enabled") : t("disabled"))}</span>
            </div>
            <p>${escapeHtml(item.description || "—")}</p>
            <div class="runtime-list">
              <div><span>${escapeHtml(t("permissions"))}</span><strong>${escapeHtml((item.permissions || []).join(", ") || "—")}</strong></div>
            </div>
            <div class="approval-actions">
              <button class="skill-toggle" data-name="${escapeHtml(item.name)}" data-enabled="${item.enabled ? "0" : "1"}">${escapeHtml(item.enabled ? t("disabled") : t("enabled"))}</button>
              <button class="reject skill-delete" data-name="${escapeHtml(item.name)}">${escapeHtml(t("delete"))}</button>
            </div>
          </article>
        `).join("") : `<div class="placeholder-card">${escapeHtml(t("skillsEmpty"))}</div>`}
      </div>
      ${renderPager("skills", page.current, page.total)}
  `;
}

function renderChannelsListSection() {
  const items = (state.summary.channels || {}).items || [];
  const page = paginate(items, "channels");
  return `
      <div class="card-list">
        ${page.items.length ? page.items.map((item) => `
          <article class="config-card">
            <div class="side-head">
              <h4>${escapeHtml(item.name)}</h4>
              <span class="status-chip">${escapeHtml(item.enabled ? t("enabled") : t("disabled"))}</span>
            </div>
            <div class="runtime-list">
              <div><span>${escapeHtml(t("target"))}</span><strong>${escapeHtml(item.target || "—")}</strong></div>
              <div><span>Status</span><strong>${escapeHtml(item.status || "—")}</strong></div>
            </div>
            <div class="approval-actions">
              <button class="channel-toggle" data-name="${escapeHtml(item.name)}" data-enabled="${item.enabled ? "0" : "1"}" data-target="${escapeHtml(item.target || "")}">${escapeHtml(item.enabled ? t("disabled") : t("enabled"))}</button>
              <button class="reject channel-delete" data-name="${escapeHtml(item.name)}">${escapeHtml(t("delete"))}</button>
            </div>
          </article>
        `).join("") : `<div class="placeholder-card">${escapeHtml(t("channelsEmpty"))}</div>`}
      </div>
      ${renderPager("channels", page.current, page.total)}
  `;
}

function renderBaselineSummaryCard() {
  const baseline = state.summary.baseline || {};
  return `
    <div class="runtime-list">
      <div><span>Time</span><strong>${escapeHtml(baseline.generated_at || t("unknown"))}</strong></div>
      <div><span>Findings</span><strong>${escapeHtml(String((baseline.findings || []).length || 0))}</strong></div>
    </div>
  `;
}

function renderCapabilitiesCard() {
  const caps = state.summary.capabilities || [];
  return `
    <div class="runtime-list">
      ${caps.length ? caps.map((item) => `<div><span>${escapeHtml(item.name)}</span><strong>${escapeHtml(item.mode)}</strong></div>`).join("") : `<div><span>—</span><strong>${escapeHtml(t("noItems"))}</strong></div>`}
    </div>
  `;
}

function renderAuditCard() {
  const audit = state.summary.audit || {};
  return `
    <div class="runtime-list">
      <div><span>Chain</span><strong>${escapeHtml((audit.chain || {}).ok ? "OK" : "FAIL")}</strong></div>
      <div><span>Recent</span><strong>${escapeHtml(String((audit.recent || []).length || 0))}</strong></div>
    </div>
  `;
}

function renderHookPanel() {
  const hook = state.summary.hook || {};
  const executionGuard = state.summary.execution_guard || {};
  return `
    <div class="runtime-list hook-panel tone-${escapeHtml(renderHookTone())}">
      <div><span>${escapeHtml(t("hookTitle"))}</span><strong id="hook-status-copy">${escapeHtml(renderHookCopy())}</strong></div>
      <div><span>${escapeHtml(t("hookPluginLoaded"))}</span><strong>${escapeHtml(hook.plugin_probe?.status === "loaded" ? t("connected") : t("disconnected"))}</strong></div>
      <div><span>${escapeHtml(t("hookRuntimeStatus"))}</span><strong>${escapeHtml(executionGuard.ready ? t("connected") : t("disconnected"))}</strong></div>
      ${hook.runtime_entry_hint ? `<div class="hook-command"><span>${escapeHtml(t("hookRuntimeCommand"))}</span><code>${escapeHtml(hook.runtime_entry_hint)}</code></div>` : ""}
      ${hook.error_detail ? `<div class="hook-detail">${escapeHtml(hook.error_detail)}</div>` : ""}
    </div>
  `;
}

function shouldPauseHeavyRefresh() {
  return Boolean(
    document.hidden ||
    state.scan.running ||
    state.sending ||
    (state.view === "chat" && isUserTyping())
  );
}

function patchToastDom() {
  const root = document.getElementById("toast-root");
  if (!root) return;
  root.innerHTML = state.toast ? `<div class="toast">${escapeHtml(state.toast)}</div>` : "";
}

function captureComposerState() {
  const input = document.getElementById("chat-input");
  if (!input) return null;
  return {
    active: document.activeElement === input,
    value: input.value,
    selectionStart: typeof input.selectionStart === "number" ? input.selectionStart : null,
    selectionEnd: typeof input.selectionEnd === "number" ? input.selectionEnd : null,
  };
}

function restoreComposerState(snapshot) {
  if (!snapshot) return;
  const input = document.getElementById("chat-input");
  if (!input) return;
  input.value = snapshot.value ?? state.draft ?? "";
  if (snapshot.active) {
    input.focus();
    if (snapshot.selectionStart !== null && snapshot.selectionEnd !== null) {
      const max = input.value.length;
      input.setSelectionRange(Math.min(snapshot.selectionStart, max), Math.min(snapshot.selectionEnd, max));
    }
  }
}

function patchComposerDom(snapshot = null) {
  const input = document.getElementById("chat-input");
  if (input && !snapshot) {
    input.value = state.draft || "";
  }
  if (input) {
    input.placeholder = t("inputPlaceholder");
  }
  const sendButton = document.getElementById("send-button");
  if (sendButton) {
    sendButton.disabled = Boolean(state.sending);
    sendButton.textContent = state.sending ? t("sending") : t("send");
  }
  const newChatButton = document.getElementById("new-chat-button");
  if (newChatButton) newChatButton.textContent = t("newChat");
  restoreComposerState(snapshot);
}

function isUserTyping() {
  const input = document.getElementById("chat-input");
  if (!input) return false;
  const active = document.activeElement === input;
  const value = input.value || state.draft || "";
  return active && value.trim().length > 0;
}

function renderHookCopy() {
  const hook = state.summary.hook || {};
  if (hook.active) return t("hookActive");
  if (hook.state === "loaded_waiting_restart") return t("hookLoadedWaitingRestart");
  if (hook.reason === "config_write_failed") return t("hookConfigFailed");
  if (hook.restart_required) return t("hookRestart");
  if (hook.state === "runtime_unreachable") return t("hookRuntimeUnreachable");
  return t("hookInactive");
}

function renderHookTone() {
  const hook = state.summary.hook || {};
  if (hook.active) return "ok";
  if (hook.state === "loaded_waiting_restart") return "warn";
  if (hook.state === "plugin_invalid" || hook.reason === "config_write_failed") return "risk";
  return "warn";
}

function syncSummarySlices() {
  state.chatStatus = state.summary.chat || state.chatStatus;
  state.conversation.pending_requests = (state.summary.console || {}).pending_requests || state.conversation.pending_requests || [];
}

function patchChatDom({ preserveComposer = true } = {}) {
  const snapshot = preserveComposer ? captureComposerState() : null;
  patchStatusDom();
  patchPendingDom();
  patchMessagesDom();
  patchComposerDom(snapshot);
  bindChatControls();
  bindPendingControls();
  patchToastDom();
}

function patchCurrentView() {
  syncSummarySlices();
  if (state.view === "chat") {
    patchChatDom();
    return;
  }
  if (state.view === "actions") {
    patchStatusDom();
    patchActionsDom();
    bindPendingControls();
    bindPagerControls();
    bindActionControls();
    patchToastDom();
    return;
  }
  if (state.view === "skills") {
    patchSkillsDom();
    patchToastDom();
    return;
  }
  if (state.view === "channels") {
    patchChannelsDom();
    patchToastDom();
    return;
  }
  if (state.view === "settings") {
    patchStatusDom();
    patchSettingsDom();
    patchToastDom();
    return;
  }
  render();
}

function setLanguage(lang) {
  state.lang = lang;
  localStorage.setItem("openclaw-guard-lang", lang);
  render();
}

function setView(view) {
  state.view = view;
  if (view === "settings") {
    void loadRuntimeDebug();
    void loadRecentLogs();
  }
  render();
}

function setPage(pageKey, next) {
  state.pages[pageKey] = Math.max(1, (state.pages[pageKey] || 1) + next);
  if (state.view === "actions" && pageKey === "actions") {
    patchActionsDom();
    bindPendingControls();
    bindPagerControls();
    bindActionControls();
    return;
  }
  if (state.view === "skills" && pageKey === "skills") {
    patchSkillsDom();
    return;
  }
  if (state.view === "channels" && pageKey === "channels") {
    patchChannelsDom();
    return;
  }
  render();
}

function scheduleChatScroll() {
  if (state.view !== "chat") return;
  window.requestAnimationFrame(() => {
    const feed = document.querySelector(".message-feed");
    if (feed) feed.scrollTop = feed.scrollHeight;
  });
}

function patchStatusDom() {
  const tone = connectionTone();
  const statusDot = document.querySelector(".status-dot");
  if (statusDot) statusDot.className = `status-dot status-${tone.tone}`;
  const topLeft = document.querySelector(".topbar-left span");
  if (topLeft) topLeft.textContent = tone.label;
  const heroStatus = document.getElementById("chat-hero-status");
  if (heroStatus) {
    heroStatus.className = `hero-status hero-${tone.tone}`;
    heroStatus.textContent = tone.label;
  }
  const heroCopy = document.getElementById("chat-hero-copy");
  if (heroCopy) heroCopy.textContent = state.chatStatus.connected ? t("onlineHint") : t("offlineHint");
  const composerHint = document.getElementById("composer-hint");
  if (composerHint) composerHint.textContent = state.chatStatus.connected ? t("onlineHint") : t("offlineHint");
  const topMeta = document.querySelectorAll(".top-meta strong");
  if (topMeta[0]) topMeta[0].textContent = state.chatStatus.current_model || t("unknown");
  if (topMeta[1]) topMeta[1].textContent = state.chatStatus.current_agent || t("unknown");
  const runtimeList = document.getElementById("runtime-list");
  if (runtimeList) runtimeList.innerHTML = renderRuntimeList();
  const modelSwitcher = document.getElementById("model-switcher");
  if (modelSwitcher) {
    const current = state.chatStatus.current_model || "";
    const options = [`<option value="">${escapeHtml(t("changeModel"))}</option>`].concat(
      (state.chatStatus.available_models || []).map((item) => `<option value="${escapeHtml(item)}" ${item === current ? "selected" : ""}>${escapeHtml(item)}</option>`)
    );
    modelSwitcher.innerHTML = options.join("");
  }
  const hookCopy = document.getElementById("hook-status-copy");
  if (hookCopy) hookCopy.textContent = renderHookCopy();
}

function patchPendingDom() {
  const pending = state.conversation.pending_requests || [];
  const pendingCount = document.getElementById("pending-count");
  if (pendingCount) pendingCount.textContent = String(pending.length);
  const pendingList = document.getElementById("pending-list");
  if (pendingList) pendingList.innerHTML = renderPendingList(pending);
  const chatFeed = document.getElementById("chat-feed");
  if (chatFeed) {
    const existing = chatFeed.querySelector(".inline-pending");
    const html = renderInlinePendingNotice();
    if (html) {
      if (existing) {
        existing.outerHTML = html;
      } else {
        chatFeed.insertAdjacentHTML("afterbegin", html);
      }
    } else if (existing) {
      existing.remove();
    }
  }
}

function patchMessagesDom() {
  const feed = document.getElementById("chat-feed");
  if (!feed) return;
  const pendingHtml = renderInlinePendingNotice();
  const messages = state.conversation.messages || [];
  const nextMessageIds = messages.map((item) => item.message_id || "");
  const messageSignature = JSON.stringify(messages.map((item) => [item.message_id || "", item.role || "", item.kind || "", item.content || ""]));
  const nextSignature = `${messageSignature}|pending:${(state.conversation.pending_requests || []).length}|typing:${state.awaitingReplyActionId || ""}`;
  const currentSignature = feed.dataset.signature || "";
  const atBottom = Math.abs((feed.scrollHeight - feed.scrollTop) - feed.clientHeight) < 48;
  if (currentSignature === nextSignature) return;
  const currentMessageSignature = feed.dataset.messageSignature || "";
  const prevIds = currentMessageSignature ? JSON.parse(currentMessageSignature) : [];
  const canAppendOnly =
    Array.isArray(prevIds) &&
    prevIds.length <= nextMessageIds.length &&
    prevIds.every((id, index) => id === nextMessageIds[index]);
  const typingNode = feed.querySelector(".message-pending");
  if (typingNode) typingNode.remove();
  const existingEmpty = feed.querySelector(".empty");
  if (pendingHtml) {
    const existing = feed.querySelector(".inline-pending");
    if (existing) existing.outerHTML = pendingHtml;
    else feed.insertAdjacentHTML("afterbegin", pendingHtml);
  } else {
    const existing = feed.querySelector(".inline-pending");
    if (existing) existing.remove();
  }
  if (canAppendOnly) {
    const existingIds = new Set(Array.from(feed.querySelectorAll("[data-message-id]")).map((node) => node.getAttribute("data-message-id") || ""));
    const newItems = messages.filter((item) => !existingIds.has(item.message_id || ""));
    if (existingEmpty && messages.length) existingEmpty.remove();
    if (newItems.length) {
      feed.insertAdjacentHTML("beforeend", newItems.map(renderMessage).join(""));
    }
  } else {
    feed.innerHTML = `${pendingHtml}${messages.length ? messages.map(renderMessage).join("") : `<div class="empty">${escapeHtml(t("noMessages"))}</div>`}`;
  }
  const typingHtml = renderTypingMessage();
  if (typingHtml) feed.insertAdjacentHTML("beforeend", typingHtml);
  feed.dataset.signature = nextSignature;
  feed.dataset.messageSignature = JSON.stringify(nextMessageIds);
  feed.dataset.messageCount = String(messages.length);
  if (atBottom || state.awaitingReplyActionId) scheduleChatScroll();
}

function patchActionsDom() {
  const actionsPanel = document.getElementById("actions-panel");
  if (actionsPanel) actionsPanel.innerHTML = renderActionColumns();
  const filters = document.getElementById("action-filters");
  if (filters) {
    filters.querySelectorAll(".filter-chip").forEach((button) => {
      button.classList.toggle("active", button.dataset.actionFilter === state.actionFilter);
    });
  }
}

function renderMessage(message) {
  const roleLabel = message.role === "user" ? t("user") : message.role === "assistant" ? t("assistant") : t("system");
  return `
    <article class="message message-${escapeHtml(message.role || "assistant")}" data-message-id="${escapeHtml(message.message_id || "")}">
      <div class="message-meta">
        <span class="message-role">${escapeHtml(roleLabel)}</span>
        <span class="message-kind">${escapeHtml(message.kind || "message")}</span>
      </div>
      <div class="message-text">
        ${String(message.content || "").split("\n").map((line) => `<p>${escapeHtml(line)}</p>`).join("")}
      </div>
    </article>
  `;
}

function renderTypingMessage() {
  if (!state.awaitingReplyActionId) return "";
  return `
    <article class="message message-assistant message-pending">
      <div class="message-meta">
        <span class="message-role">${escapeHtml(t("assistant"))}</span>
        <span class="message-kind">${escapeHtml(t("thinking"))}</span>
      </div>
      <div class="message-text">
        <p>${escapeHtml(t("thinking"))}</p>
      </div>
    </article>
  `;
}

function renderPendingList(items) {
  return items.length ? items.map(renderPendingCard).join("") : `<div class="empty">${escapeHtml(t("noPending"))}</div>`;
}

function renderRuntimeList() {
  return `
    <div><span>${escapeHtml(t("profile"))}</span><strong>${escapeHtml((state.summary.target || {}).profile || t("unknown"))}</strong></div>
    <div><span>${escapeHtml(t("workspace"))}</span><strong>${escapeHtml((state.summary.target || {}).workspace_path || t("unknown"))}</strong></div>
    <div class="runtime-inline">
      <div><span>${escapeHtml(t("model"))}</span><strong>${escapeHtml(state.chatStatus.current_model || t("unknown"))}</strong></div>
      <div><span>${escapeHtml(t("agent"))}</span><strong>${escapeHtml(state.chatStatus.current_agent || t("unknown"))}</strong></div>
    </div>
  `;
}

function renderActionColumns() {
  const items = (state.summary.actions || {}).items || [];
  const filtered = items.filter((item) => item.status === state.actionFilter);
  const page = paginate(filtered, "actions");
  return `
    <div class="approval-list">
      ${page.items.length ? page.items.map(renderPendingCard).join("") : `<div class="empty">${escapeHtml(t("noActions"))}</div>`}
    </div>
    ${renderPager("actions", page.current, page.total)}
  `;
}

function renderInlinePendingNotice() {
  const pending = state.conversation.pending_requests || [];
  if (!pending.length || state.view !== "chat") return "";
  const item = pending[0];
  const decision = item.decision || {};
  return `
    <section class="inline-pending tone-${escapeHtml(decision.risk_level || "dangerous")}">
      <div class="inline-pending-copy">
        <strong>${escapeHtml(t("pendingInlineTitle"))}</strong>
        <span>${escapeHtml(item.source_message || item.target_summary || "")}</span>
      </div>
      <button id="open-actions-button">${escapeHtml(t("openActions"))}</button>
    </section>
  `;
}

function renderPendingCard(item) {
  const decision = item.decision || {};
  const isPending = item.status === "pending_approval";
  const executionMessage = item.execution_result?.user_message || item.execution_result?.message || "";
  const event = item.event || {};
  const rawIntent = event.raw_payload?.raw_user_intent || item.source_message || "";
  return `
    <article class="approval-card tone-${escapeHtml(decision.risk_level || "safe")}">
      <div class="approval-head">
        <span class="risk-chip">${escapeHtml(riskLabel(decision.risk_level))}</span>
        <span class="status-chip">${escapeHtml(statusLabel(item.status))}</span>
      </div>
      <h4>${escapeHtml(actionTitle(item))}</h4>
      ${rawIntent ? `<div class="approval-request">${escapeHtml(rawIntent)}</div>` : ""}
      <p>${escapeHtml(decision.reason || "")}</p>
      <div class="approval-meta">
        <span>${escapeHtml(actionTypeLabel((item.event || {}).action_type || ""))}</span>
      </div>
      ${executionMessage ? `<div class="execution-note">${escapeHtml(executionMessage)}</div>` : ""}
      ${isPending ? `
        <div class="approval-actions">
          ${(decision.requires_second_confirmation)
            ? `<input class="confirm-input" data-confirm="${escapeHtml(item.action_id)}" placeholder="${escapeHtml(`${t("confirmWord")} ${decision.confirmation_word || "EXECUTE"}`)}">`
            : ""}
          <button class="primary approve-action" data-id="${escapeHtml(item.action_id)}">${escapeHtml(t("approve"))}</button>
          <button class="reject-action" data-id="${escapeHtml(item.action_id)}">${escapeHtml(t("reject"))}</button>
        </div>
      ` : ""}
      <details>
        <summary>${escapeHtml(t("details"))}</summary>
        <pre>${escapeHtml(JSON.stringify(item, null, 2))}</pre>
      </details>
    </article>
  `;
}

function renderScanPanel() {
  const scanProgress = Math.max(0, Math.min(100, Number(state.scan.progress || 0)));
  const cards = scanCards();
  const selected = selectedScanCard();
  return `
      <article id="scan-panel-host" class="side-card scan-card ${state.scan.running ? "scan-running" : ""}">
        <div class="side-head"><h3>${escapeHtml(t("scanTitle"))}</h3></div>
        <div class="scan-shell">
          <div class="scan-copy">
            <strong id="scan-state-label">${escapeHtml(state.scan.running ? t("scanRunning") : state.scan.result ? t("scanFinished") : t("scanIdle"))}</strong>
            <p>${escapeHtml(t("scanHint"))}</p>
            <div class="scan-phase-row">
              <span>${escapeHtml(t("scanProgress"))}</span>
              <strong id="scan-phase-label">${escapeHtml(state.scan.phase || t("scanStage_prepare"))}</strong>
            </div>
            <div class="scan-stage-track"><span id="scan-stage-progress" style="width:${escapeHtml(String(scanProgress))}%"></span></div>
            <div class="settings-actions">
              <button id="run-baseline" class="primary" ${state.scan.running ? "disabled" : ""}>${escapeHtml(state.scan.running ? t("scanRunning") : t("scanStart"))}</button>
              <button id="export-audit">${escapeHtml(t("audit"))}</button>
            </div>
          </div>
        </div>
        <div class="scan-grid">
          ${cards.map((card) => {
            const progress = scanProgressValue(card, scanProgress);
            return `
            <button
              class="scan-item tone-${escapeHtml(card.tone)} ${state.scan.selected === card.key ? "active" : ""} ${state.scan.running && state.scan.selected === card.key ? "running" : ""}"
              data-scan-key="${escapeHtml(card.key)}"
              style="--scan-progress:${escapeHtml(String(progress))}; --scan-progress-frac:${escapeHtml(String(progress / 100))};"
            >
              <div class="scan-item-border"></div>
              <div class="scan-item-body">
                <div class="scan-item-head">
                  <strong>${escapeHtml(card.title)}</strong>
                  <span>${escapeHtml(card.statusLabel)}</span>
                </div>
                <div class="scan-item-overview">
                  <div class="scan-metric">
                    <label>${escapeHtml(t("scanIssues"))}</label>
                    <strong>${escapeHtml(String(card.count))}</strong>
                  </div>
                  <div class="scan-metric">
                    <label>${escapeHtml(t("scanAssets"))}</label>
                    <strong>${escapeHtml(String(card.assets.length))}</strong>
                  </div>
                  <div class="scan-metric">
                    <label>${escapeHtml(t("scanChecks"))}</label>
                    <strong>${escapeHtml(String(card.totalChecks))}</strong>
                  </div>
                </div>
              </div>
            </button>`;
          }).join("")}
        </div>
        <div class="scan-detail">
          <div class="side-head">
            <h3>${escapeHtml(selected?.title || t("scanDetails"))}</h3>
            <span class="status-chip">${escapeHtml(selected?.statusLabel || "")}</span>
          </div>
          <div class="scan-detail-list">
            ${(selected?.checks || []).length ? (selected.checks || []).map((item) => `
              <article class="scan-detail-card tone-${escapeHtml(item.status || "ok")}">
                <div class="scan-detail-head">
                  <div class="scan-detail-title">
                    <strong>${escapeHtml(item.title || "")}</strong>
                    <span>${escapeHtml(item.check_id || "")}</span>
                  </div>
                  <div class="scan-detail-tags">
                    <span class="risk-chip">${escapeHtml(item.status === "ok" ? t("scanStatus_ok") : item.status === "warn" ? t("scanStatus_warn") : t("scanStatus_risk"))}</span>
                    <button class="bulb-btn" type="button" data-solution-id="${escapeHtml(item.check_id || "")}" title="${escapeHtml(t("showSolution"))}">💡</button>
                  </div>
                </div>
                <p>${escapeHtml(item.description || "")}</p>
                <div class="scan-detail-evidence">${escapeHtml(JSON.stringify(item.evidence || {}))}</div>
                <div class="scan-detail-rec" id="solution-${escapeHtml(item.check_id || "")}" hidden>
                  <strong>${escapeHtml(t("solution"))}</strong>
                  <div>${escapeHtml(item.recommendation || "")}</div>
                </div>
              </article>
            `).join("") : `<div class="placeholder-card">${escapeHtml(t("noItems"))}</div>`}
          </div>
        </div>
      </article>
  `;
}

function renderChatView() {
  const messages = state.conversation.messages || [];
  const pending = state.conversation.pending_requests || [];
  return `
    <section class="chat-shell">
      <div class="chat-main">
        <div class="message-feed" id="chat-feed">
          ${renderInlinePendingNotice()}
          ${messages.length ? messages.map(renderMessage).join("") : `<div class="empty">${escapeHtml(t("noMessages"))}</div>`}
          ${renderTypingMessage()}
        </div>
        <div class="composer">
          <textarea id="chat-input" placeholder="${escapeHtml(t("inputPlaceholder"))}">${escapeHtml(state.draft)}</textarea>
          <div class="composer-bar">
            <div class="composer-hint" id="composer-hint">${escapeHtml(state.chatStatus.connected ? t("onlineHint") : t("offlineHint"))}</div>
            <button id="send-button" class="primary" ${state.sending ? "disabled" : ""}>${escapeHtml(state.sending ? t("sending") : t("send"))}</button>
          </div>
          <div class="composer-foot">
            <button id="new-chat-button" class="quiet-button">${escapeHtml(t("newChat"))}</button>
          </div>
        </div>
      </div>
      <aside class="chat-side">
        <section class="side-card">
          <div class="side-head">
            <h3>${escapeHtml(t("pendingTitle"))}</h3>
            <span id="pending-count">${escapeHtml(String(pending.length))}</span>
          </div>
          <div class="approval-list" id="pending-list">
            ${renderPendingList(pending)}
          </div>
        </section>
        <section class="side-card">
          <div class="side-head">
            <h3>${escapeHtml(t("runtime"))}</h3>
          </div>
          <div class="runtime-list" id="runtime-list">
            ${renderRuntimeList()}
          </div>
        </section>
      </aside>
    </section>
  `;
}

function renderActionsView() {
  const items = (state.summary.actions || {}).items || [];
  const statusOrder = ["pending_approval", "blocked", "executed", "failed"];
  const filtered = items.filter((item) => item.status === state.actionFilter);
  const page = paginate(filtered, "actions");
  return `
    <section class="stack-view">
      <div class="action-filters" id="action-filters">
        ${statusOrder.map((status) => `
          <button class="filter-chip ${state.actionFilter === status ? "active" : ""}" data-action-filter="${status}">
            ${escapeHtml(statusLabel(status))}
          </button>
        `).join("")}
      </div>
      <div class="action-column" id="actions-panel">
        <div class="approval-list">
          ${page.items.length ? page.items.map(renderPendingCard).join("") : `<div class="empty">${escapeHtml(t("noActions"))}</div>`}
        </div>
        ${renderPager("actions", page.current, page.total)}
      </div>
    </section>
  `;
}

function renderSkillsView() {
  return `
    <section class="single-panel">
      <div class="side-head"><h3>${escapeHtml(t("skills"))}</h3></div>
      <div class="editor-row">
        <input id="skill-name" placeholder="skill name">
        <input id="skill-description" placeholder="${escapeHtml(t("description"))}">
        <input id="skill-permissions" placeholder="${escapeHtml(t("permissions"))}: read,write,exec">
        <label class="toggle"><input id="skill-enabled" type="checkbox" checked> ${escapeHtml(t("enabled"))}</label>
        <button id="save-skill">${escapeHtml(t("addSkill"))}</button>
      </div>
      <div id="skills-list-host">
        ${renderSkillsListSection()}
      </div>
    </section>
  `;
}

function renderChannelsView() {
  return `
    <section class="single-panel">
      <div class="side-head"><h3>${escapeHtml(t("channels"))}</h3></div>
      <div class="editor-row">
        <input id="channel-name" placeholder="channel name">
        <input id="channel-target" placeholder="${escapeHtml(t("target"))}">
        <label class="toggle"><input id="channel-enabled" type="checkbox" checked> ${escapeHtml(t("enabled"))}</label>
        <button id="save-channel">${escapeHtml(t("addChannel"))}</button>
      </div>
      <div id="channels-list-host">
        ${renderChannelsListSection()}
      </div>
    </section>
  `;
}

function renderSettingsView() {
  const prefs = state.summary.preferences || {};
  return `
    <section class="single-panel settings-grid">
      ${renderScanPanel()}
      <article class="side-card" id="settings-hook-card">
        <div class="side-head"><h3>${escapeHtml(t("securitySettings"))}</h3></div>
        <p class="setting-copy">${escapeHtml(t("settingsHint"))}</p>
        <div id="hook-panel-host">${renderHookPanel()}</div>
        <div class="settings-actions slim-actions">
          <button id="refresh-runtime">${escapeHtml(t("runtimeRefresh"))}</button>
          <button id="load-debug">${escapeHtml(t("loadDebug"))}</button>
          <button id="reload-logs">${escapeHtml(t("reloadLogs"))}</button>
        </div>
        <div id="runtime-debug-host">
          ${renderRuntimeDebugPanel()}
        </div>
      </article>
      <article class="side-card">
        <div class="side-head"><h3>${escapeHtml(t("settings"))}</h3></div>
        <div class="editor-col">
          <label>${escapeHtml(t("guardMode"))}
            <select id="guard-mode">
              <option value="strict" ${prefs.guard_mode === "strict" ? "selected" : ""}>${escapeHtml(t("strict"))}</option>
              <option value="balanced" ${prefs.guard_mode === "balanced" ? "selected" : ""}>${escapeHtml(t("balanced"))}</option>
            </select>
          </label>
          <label class="toggle"><input id="reply-scan" type="checkbox" ${prefs.reply_scan === false ? "" : "checked"}> ${escapeHtml(t("replyScan"))}</label>
          <button id="save-preferences">${escapeHtml(t("save"))}</button>
        </div>
      </article>
      <article class="side-card">
        <div class="side-head"><h3>${escapeHtml(t("baseline"))}</h3></div>
        <div id="baseline-summary-host">${renderBaselineSummaryCard()}</div>
      </article>
      <article class="side-card">
        <div class="side-head"><h3>${escapeHtml(t("capabilities"))}</h3></div>
        <div id="capabilities-host">${renderCapabilitiesCard()}</div>
      </article>
      <article class="side-card">
        <div class="side-head"><h3>Audit</h3></div>
        <div id="audit-summary-host">${renderAuditCard()}</div>
      </article>
    </section>
  `;
}

function patchScanDom() {
  const host = document.getElementById("scan-panel-host");
  if (!host) return;
  host.outerHTML = renderScanPanel();
  bindSettingsControls();
  bindActionControls();
}

function patchSettingsDom() {
  const hookHost = document.getElementById("hook-panel-host");
  if (hookHost) hookHost.innerHTML = renderHookPanel();
  const host = document.getElementById("runtime-debug-host");
  if (host) host.innerHTML = renderRuntimeDebugPanel();
  const baselineHost = document.getElementById("baseline-summary-host");
  if (baselineHost) baselineHost.innerHTML = renderBaselineSummaryCard();
  const capabilityHost = document.getElementById("capabilities-host");
  if (capabilityHost) capabilityHost.innerHTML = renderCapabilitiesCard();
  const auditHost = document.getElementById("audit-summary-host");
  if (auditHost) auditHost.innerHTML = renderAuditCard();
  const guardMode = document.getElementById("guard-mode");
  if (guardMode) guardMode.value = state.summary.preferences?.guard_mode || "strict";
  const replyScan = document.getElementById("reply-scan");
  if (replyScan) replyScan.checked = state.summary.preferences?.reply_scan !== false;
  bindSettingsControls();
  bindActionControls();
}

function patchSkillsDom() {
  if (state.view !== "skills") return;
  const host = document.getElementById("skills-list-host");
  if (!host) return;
  host.innerHTML = renderSkillsListSection();
  bindSkillControls();
  bindPagerControls();
}

function patchChannelsDom() {
  if (state.view !== "channels") return;
  const host = document.getElementById("channels-list-host");
  if (!host) return;
  host.innerHTML = renderChannelsListSection();
  bindChannelControls();
  bindPagerControls();
}

function renderMainView() {
  if (state.view === "actions") return renderActionsView();
  if (state.view === "skills") return renderSkillsView();
  if (state.view === "channels") return renderChannelsView();
  if (state.view === "settings") return renderSettingsView();
  return renderChatView();
}

function render() {
  const root = document.getElementById("app");
  const activeBefore = document.activeElement?.id;
  const inputBefore = document.getElementById("chat-input");
  const selectionStart = inputBefore && typeof inputBefore.selectionStart === "number" ? inputBefore.selectionStart : null;
  const selectionEnd = inputBefore && typeof inputBefore.selectionEnd === "number" ? inputBefore.selectionEnd : null;
  if (inputBefore) state.draft = inputBefore.value || state.draft;
  const tone = connectionTone();
  const modelOptions = (state.chatStatus.available_models || []).map((item) => `
    <option value="${escapeHtml(item)}" ${item === state.chatStatus.current_model ? "selected" : ""}>${escapeHtml(item)}</option>
  `).join("");
  root.innerHTML = `
    <div class="shell">
      <aside class="sidebar">
        <div class="brand">
          <div class="brand-mark">OG</div>
          <div>
            <h2>${escapeHtml(t("appName"))}</h2>
            <p>${escapeHtml(t("appSub"))}</p>
          </div>
        </div>
        <nav class="nav">
          ${["chat", "actions", "skills", "channels", "settings"].map((view) => `
            <button class="nav-btn ${state.view === view ? "active" : ""}" data-view="${view}">${escapeHtml(t(view))}</button>
          `).join("")}
        </nav>
      </aside>
      <div class="workspace">
        <header class="topbar">
          <div class="topbar-left">
            <div class="status-dot status-${escapeHtml(tone.tone)}"></div>
            <span>${escapeHtml(tone.label)}</span>
          </div>
          <div class="topbar-center">
            <div class="top-pair">
              <div class="top-meta"><span>${escapeHtml(t("model"))}</span><strong>${escapeHtml(state.chatStatus.current_model || t("unknown"))}</strong></div>
              <div class="top-meta"><span>${escapeHtml(t("agent"))}</span><strong>${escapeHtml(state.chatStatus.current_agent || t("unknown"))}</strong></div>
            </div>
          </div>
          <div class="topbar-right">
            <select id="model-switcher" title="${escapeHtml(t("changeModel"))}">
              <option value="">${escapeHtml(t("changeModel"))}</option>
              ${modelOptions}
            </select>
            <div class="lang-switch">
              <button class="${state.lang === "zh" ? "active" : ""}" data-lang="zh">中文</button>
              <button class="${state.lang === "en" ? "active" : ""}" data-lang="en">English</button>
            </div>
            <button id="refresh-button">${escapeHtml(t("refresh"))}</button>
          </div>
        </header>
        <main class="main">
          ${renderMainView()}
          ${renderFooter()}
        </main>
      </div>
      <div id="toast-root">${state.toast ? `<div class="toast">${escapeHtml(state.toast)}</div>` : ""}</div>
    </div>
  `;
  bind();
  const inputAfter = document.getElementById("chat-input");
  if (inputAfter) {
    inputAfter.value = state.draft || "";
    if (activeBefore === "chat-input") {
      inputAfter.focus();
      if (selectionStart !== null && selectionEnd !== null) {
        const max = inputAfter.value.length;
        inputAfter.setSelectionRange(Math.min(selectionStart, max), Math.min(selectionEnd, max));
      }
    }
  }
  scheduleChatScroll();
}

async function refreshStatusOnly() {
  try {
    state.chatStatus = await api("/api/chat/status");
    patchStatusDom();
    patchToastDom();
  } catch (_error) {}
}

function rememberDraft() {
  const input = document.getElementById("chat-input");
  if (input) state.draft = input.value || "";
}

async function refreshAll() {
  rememberDraft();
  if (shouldPauseHeavyRefresh()) {
    await refreshStatusOnly();
    return;
  }
  const [summary, conversation] = await Promise.all([
    api("/api/summary"),
    api("/api/conversation"),
  ]);
  state.summary = summary;
  state.chatStatus = summary.chat || state.chatStatus;
  state.conversation = conversation;
  if (isUserTyping()) {
    patchStatusDom();
    patchToastDom();
    return;
  }
  patchCurrentView();
}

async function refreshCurrentView() {
  if (state.view === "chat") {
    await refreshConversation();
    return;
  }
  if (state.view === "actions") {
    await refreshActionsOnly();
    return;
  }
  if (state.view === "settings") {
    await Promise.all([refreshStatusOnly(), loadRuntimeDebug(), loadRecentLogs()]);
    patchSettingsDom();
    return;
  }
  await refreshStatusOnly();
}

async function refreshConversation() {
  rememberDraft();
  try {
    const [payload, conversation] = await Promise.all([
      api("/api/chat/history"),
      api("/api/conversation"),
    ]);
    state.conversation.messages = payload.items || [];
    state.chatStatus = payload.status || state.chatStatus;
    state.conversation.pending_requests = conversation.pending_requests || [];
  } catch (_error) {}
  if (shouldPauseHeavyRefresh()) {
    patchStatusDom();
    patchToastDom();
    return;
  }
  patchChatDom();
}

async function refreshActionsOnly() {
  try {
    const payload = await api("/api/actions");
    const items = payload.items || [];
    state.summary.actions = { ...(state.summary.actions || {}), items };
    state.conversation.pending_requests = items.filter((item) => item.status === "pending_approval").slice(0, 8);
  } catch (_error) {}
  if (state.view === "actions") {
    patchActionsDom();
    bindPendingControls();
    bindPagerControls();
    bindActionControls();
  } else if (state.view === "chat") {
    patchPendingDom();
    bindPendingControls();
  }
}

async function loadRuntimeDebug() {
  try {
    state.runtimeDebug = await api("/api/chat/debug");
    if (state.view === "settings") patchSettingsDom();
  } catch (error) {
    toast(errorMessage(error.payload));
  }
}

async function loadRecentLogs() {
  try {
    const payload = await api("/api/debug/logs");
    state.debugLogs = payload.items || [];
    if (state.view === "settings") patchSettingsDom();
  } catch (error) {
    toast(errorMessage(error.payload));
  }
}

async function refreshRuntime() {
  try {
    state.runtimeDebug = await api("/api/runtime/refresh");
    await refreshStatusOnly();
    if (state.view === "settings") patchSettingsDom();
    toast(t("saved"));
  } catch (error) {
    toast(errorMessage(error.payload));
  }
}

function stopReplyPolling() {
  if (window.__guardReplyPollTimer) {
    window.clearTimeout(window.__guardReplyPollTimer);
    window.__guardReplyPollTimer = null;
  }
}

async function pollReply(actionId) {
  if (!actionId) return;
  stopReplyPolling();
  try {
    const payload = await api("/api/chat/poll", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action_id: actionId, timeout_ms: 1400 }),
    });
    state.conversation.messages = payload.messages || state.conversation.messages;
    if (payload.done) {
      state.awaitingReplyActionId = null;
      const failedMessage = payload.action?.execution_result?.user_message || payload.action?.execution_result?.message;
      if (payload.action?.status === "failed" && failedMessage) {
        toast(failedMessage);
      }
      await refreshAll();
      return;
    }
    state.awaitingReplyActionId = actionId;
    if (!shouldPauseHeavyRefresh()) patchChatDom();
    window.__guardReplyPollTimer = window.setTimeout(() => { void pollReply(actionId); }, isUserTyping() ? 1400 : 900);
  } catch (error) {
    state.awaitingReplyActionId = null;
    patchChatDom();
    toast(errorMessage(error.payload));
  }
}

function stopActionWatcher() {
  if (window.__guardActionWatchTimer) {
    window.clearTimeout(window.__guardActionWatchTimer);
    window.__guardActionWatchTimer = null;
  }
}

async function watchAction(actionId) {
  if (!actionId) return;
  stopActionWatcher();
  state.actionWatchingId = actionId;
  try {
    const payload = await api("/api/actions");
    const items = payload.items || [];
    const current = items.find((item) => item.action_id === actionId);
    if (!current) {
      state.actionWatchingId = null;
      await refreshAll();
      return;
    }
    state.summary.actions = { ...(state.summary.actions || {}), items };
    state.conversation.pending_requests = items.filter((item) => item.status === "pending_approval").slice(0, 8);
    if (state.view === "actions") {
      patchActionsDom();
      bindPendingControls();
      bindPagerControls();
      bindActionControls();
    } else if (state.view === "chat") {
      patchPendingDom();
      bindPendingControls();
    }
    if (["executed", "failed", "blocked", "rejected"].includes(current.status)) {
      state.actionWatchingId = null;
      if (current.execution_result?.user_message) toast(current.execution_result.user_message);
      return;
    }
    window.__guardActionWatchTimer = window.setTimeout(() => { void watchAction(actionId); }, 900);
  } catch (_error) {
    state.actionWatchingId = null;
  }
}

async function handleSend() {
  stopActionWatcher();
  const input = document.getElementById("chat-input");
  const message = (input?.value || "").trim();
  if (!message) {
    toast(t("error_message_empty"));
    return;
  }
  state.sending = true;
  state.draft = message;
  const optimistic = {
    message_id: `draft-${Date.now()}`,
    role: "user",
    content: message,
    kind: "request",
    metadata: { optimistic: true },
  };
  state.conversation.messages = [...(state.conversation.messages || []), optimistic];
  patchChatDom({ preserveComposer: false });
  try {
    const payload = await api("/api/chat/send", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message }),
      });
    if (payload.status === "pending_confirmation") {
      state.conversation.messages = payload.messages || state.conversation.messages;
      state.awaitingReplyActionId = null;
      state.draft = "";
      if (input) input.value = "";
      toast(errorMessage(payload));
      await refreshAll();
      return;
    }
    if (payload.status === "blocked") {
      state.conversation.messages = payload.messages || state.conversation.messages;
      state.awaitingReplyActionId = null;
      state.draft = "";
      if (input) input.value = "";
      toast(errorMessage(payload));
      await refreshAll();
      return;
    }
    state.conversation.messages = payload.messages || [];
    state.awaitingReplyActionId = payload.action?.action_id || null;
    state.draft = "";
    if (input) input.value = "";
    patchChatDom({ preserveComposer: false });
    if (state.awaitingReplyActionId) {
      void pollReply(state.awaitingReplyActionId);
    } else {
      await refreshAll();
    }
  } catch (error) {
    state.conversation.messages = (state.conversation.messages || []).filter((item) => item.message_id !== optimistic.message_id);
    patchChatDom();
    toast(errorMessage(error.payload));
  } finally {
    state.sending = false;
    patchComposerDom(captureComposerState());
  }
}

async function approveAction(actionId) {
  const confirmInput = document.querySelector(`[data-confirm="${actionId}"]`);
  try {
    const payload = await api("/api/actions/approve", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action_id: actionId, confirmation_text: confirmInput ? confirmInput.value : "" }),
    });
    if (payload.messages) state.conversation.messages = payload.messages;
    if ((payload.action || {}).event?.metadata?.hook_bridge) {
      toast(payload.reply_text || statusLabel((payload.action || {}).status || "approved"));
      await refreshAll();
      void watchAction((payload.action || {}).action_id);
      return;
    }
    if (payload.action?.status === "executing") {
      state.awaitingReplyActionId = payload.action.action_id;
      toast(statusLabel("executing"));
      setView("chat");
      void pollReply(payload.action.action_id);
      return;
    }
    toast(payload.reply_text || statusLabel((payload.action || payload).status || "approved"));
    await refreshAll();
    setView("chat");
  } catch (error) {
    toast(errorMessage(error.payload));
  }
}

async function rejectAction(actionId) {
  try {
    await api("/api/actions/reject", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action_id: actionId }),
    });
    toast(t("status_rejected"));
    await refreshAll();
  } catch (error) {
    toast(errorMessage(error.payload));
  }
}

async function runBaseline() {
  const phases = [
    { key: "scanStage_prepare", progress: 18 },
    { key: "scanStage_config", progress: 42 },
    { key: "scanStage_runtime", progress: 71 },
    { key: "scanStage_audit", progress: 92 },
  ];
  const minimumDuration = 2600;
  let phaseIndex = 0;
  state.scan.running = true;
  state.scan.result = null;
  state.scan.phase = t(phases[0].key);
  state.scan.progress = phases[0].progress;
  patchScanDom();
  const timer = window.setInterval(() => {
    phaseIndex = Math.min(phaseIndex + 1, phases.length - 1);
    state.scan.phase = t(phases[phaseIndex].key);
    state.scan.progress = phases[phaseIndex].progress;
    if (state.view === "settings") patchScanDom();
  }, 520);
  try {
    const startedAt = Date.now();
    const payload = await api("/api/baseline/run", { method: "POST" });
    const remaining = Math.max(0, minimumDuration - (Date.now() - startedAt));
    if (remaining) {
      await new Promise((resolve) => window.setTimeout(resolve, remaining));
    }
    state.scan.running = false;
    state.scan.result = payload;
    state.scan.phase = t("scanFinished");
    state.scan.progress = 100;
    toast(t("scanFinished"));
    await refreshAll();
  } catch (error) {
    state.scan.running = false;
    state.scan.phase = t("error_default");
    toast(errorMessage(error.payload));
  } finally {
    window.clearInterval(timer);
    if (state.view === "settings") patchScanDom();
  }
}

async function exportAudit() {
  try {
    const payload = await api("/api/audit/export", { method: "POST" });
    toast(`${payload.json}`);
  } catch (error) {
    toast(errorMessage(error.payload));
  }
}

async function saveSkill(payload) {
  try {
    const result = await api("/api/skills/save", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    state.summary.skills = result.skills || state.summary.skills;
    toast(t("saved"));
    state.pages.skills = 1;
    patchSkillsDom();
  } catch (error) {
    toast(errorMessage(error.payload));
  }
}

async function deleteSkill(name) {
  try {
    const result = await api("/api/skills/delete", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name }),
    });
    state.summary.skills = result.skills || state.summary.skills;
    toast(t("saved"));
    patchSkillsDom();
  } catch (error) {
    toast(errorMessage(error.payload));
  }
}

async function saveChannel(payload) {
  try {
    const result = await api("/api/channels/save", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    state.summary.channels = result.channels || state.summary.channels;
    toast(t("saved"));
    state.pages.channels = 1;
    patchChannelsDom();
  } catch (error) {
    toast(errorMessage(error.payload));
  }
}

async function deleteChannel(name) {
  try {
    const result = await api("/api/channels/delete", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name }),
    });
    state.summary.channels = result.channels || state.summary.channels;
    toast(t("saved"));
    patchChannelsDom();
  } catch (error) {
    toast(errorMessage(error.payload));
  }
}

async function savePreferences() {
  try {
    const result = await api("/api/preferences/save", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        guard_mode: document.getElementById("guard-mode")?.value || "strict",
        reply_scan: Boolean(document.getElementById("reply-scan")?.checked),
      }),
    });
    state.summary.preferences = result;
    toast(t("saved"));
    if (state.view === "settings") patchSettingsDom();
  } catch (error) {
    toast(errorMessage(error.payload));
  }
}

async function startNewChat() {
  stopReplyPolling();
  stopActionWatcher();
  try {
    const payload = await api("/api/chat/new", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    state.awaitingReplyActionId = null;
    state.draft = "";
    state.conversation.messages = payload.messages || [];
    state.view = "chat";
    patchChatDom({ preserveComposer: false });
  } catch (error) {
    toast(errorMessage(error.payload));
  }
}

async function changeModel(value) {
  if (!value) return;
  try {
    await api("/api/chat/model", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ model: value }),
    });
    toast(`${t("model")} → ${value}`);
    await refreshStatusOnly();
    if (state.view === "settings") {
      await loadRuntimeDebug();
    } else {
      await refreshConversation();
    }
  } catch (error) {
    toast(errorMessage(error.payload) || t("modelSwitchFailed"));
  }
}

function bindGlobalControls() {
  document.querySelectorAll(".nav-btn").forEach((button) => { button.onclick = () => setView(button.dataset.view); });
  document.querySelectorAll(".lang-switch button").forEach((button) => { button.onclick = () => setLanguage(button.dataset.lang); });
  const refreshButton = document.getElementById("refresh-button");
  if (refreshButton) refreshButton.onclick = () => { void refreshCurrentView(); };
  const modelSwitcher = document.getElementById("model-switcher");
  if (modelSwitcher) modelSwitcher.onchange = (event) => { void changeModel(event.target.value); };
}

function bindChatControls() {
  const newChatButton = document.getElementById("new-chat-button");
  if (newChatButton) newChatButton.onclick = () => { void startNewChat(); };
  const openActionsButton = document.getElementById("open-actions-button");
  if (openActionsButton) openActionsButton.onclick = () => { setView("actions"); };
  const sendButton = document.getElementById("send-button");
  if (sendButton) sendButton.onclick = () => { void handleSend(); };
  const input = document.getElementById("chat-input");
  if (input) input.oninput = (event) => {
    state.draft = event.target.value || "";
  };
  if (input) input.onkeydown = (event) => {
    if (event.key === "Enter" && !event.shiftKey) {
      event.preventDefault();
      void handleSend();
    }
  };
}

function bindPendingControls() {
  document.querySelectorAll(".approve-action").forEach((button) => { button.onclick = () => { void approveAction(button.dataset.id); }; });
  document.querySelectorAll(".reject-action").forEach((button) => { button.onclick = () => { void rejectAction(button.dataset.id); }; });
}

function bindSettingsControls() {
  const runBaselineButton = document.getElementById("run-baseline");
  if (runBaselineButton) runBaselineButton.onclick = () => { void runBaseline(); };
  const exportAuditButton = document.getElementById("export-audit");
  if (exportAuditButton) exportAuditButton.onclick = () => { void exportAudit(); };
  const savePreferencesButton = document.getElementById("save-preferences");
  if (savePreferencesButton) savePreferencesButton.onclick = () => { void savePreferences(); };
}

function bindSkillControls() {
  const saveSkillButton = document.getElementById("save-skill");
  if (saveSkillButton) saveSkillButton.onclick = () => {
    const name = document.getElementById("skill-name")?.value || "";
    const description = document.getElementById("skill-description")?.value || "";
    const permissions = (document.getElementById("skill-permissions")?.value || "").split(",").map((item) => item.trim()).filter(Boolean);
    const enabled = Boolean(document.getElementById("skill-enabled")?.checked);
    void saveSkill({ name, description, permissions, enabled });
  };
  document.querySelectorAll(".skill-toggle").forEach((button) => { button.onclick = () => {
    void saveSkill({ name: button.dataset.name, enabled: button.dataset.enabled === "1" });
  }; });
  document.querySelectorAll(".skill-delete").forEach((button) => { button.onclick = () => {
    void deleteSkill(button.dataset.name);
  }; });
}

function bindChannelControls() {
  const saveChannelButton = document.getElementById("save-channel");
  if (saveChannelButton) saveChannelButton.onclick = () => {
    const name = document.getElementById("channel-name")?.value || "";
    const target = document.getElementById("channel-target")?.value || "";
    const enabled = Boolean(document.getElementById("channel-enabled")?.checked);
    void saveChannel({ name, target, enabled });
  };
  document.querySelectorAll(".channel-toggle").forEach((button) => { button.onclick = () => {
    void saveChannel({ name: button.dataset.name, target: button.dataset.target || "", enabled: button.dataset.enabled === "1" });
  }; });
  document.querySelectorAll(".channel-delete").forEach((button) => { button.onclick = () => {
    void deleteChannel(button.dataset.name);
  }; });
}

function bindPagerControls() {
  document.querySelectorAll(".pager-btn").forEach((button) => { button.onclick = () => {
    void setPage(button.dataset.pageKey, button.dataset.pageNext === "1" ? 1 : -1);
  }; });
}

function bindActionControls() {
  document.querySelectorAll(".filter-chip").forEach((button) => { button.onclick = () => {
    state.actionFilter = button.dataset.actionFilter || "pending_approval";
    state.pages.actions = 1;
    patchActionsDom();
    bindPendingControls();
    bindPagerControls();
    bindActionControls();
  }; });
  document.querySelectorAll(".scan-item").forEach((button) => { button.onclick = () => {
    state.scan.selected = button.dataset.scanKey || "config";
    patchScanDom();
  }; });
  document.querySelectorAll(".bulb-btn").forEach((button) => { button.onclick = () => {
    const target = document.getElementById(`solution-${button.dataset.solutionId || ""}`);
    if (target) target.hidden = !target.hidden;
  }; });
}

function bind() {
  bindGlobalControls();
  bindChatControls();
  bindPendingControls();
  bindSettingsControls();
  bindSkillControls();
  bindChannelControls();
  bindPagerControls();
  bindActionControls();
}

let __guardHeartbeatTimer = null;

function scheduleHeartbeat(delay = 7000) {
  if (__guardHeartbeatTimer) window.clearTimeout(__guardHeartbeatTimer);
  __guardHeartbeatTimer = window.setTimeout(async () => {
    try {
      await refreshStatusOnly();
      if (!state.awaitingReplyActionId && !state.actionWatchingId && !shouldPauseHeavyRefresh()) {
        if (state.view === "chat") {
          await refreshConversation();
        } else if (state.view === "actions") {
          await refreshActionsOnly();
        } else if (state.view === "settings") {
          await Promise.all([loadRuntimeDebug(), loadRecentLogs()]);
        }
      }
    } finally {
      scheduleHeartbeat(shouldPauseHeavyRefresh() ? 10000 : 7000);
    }
  }, delay);
}

render();
void refreshConversation();
scheduleHeartbeat();
"""


def _styles() -> str:
    return r"""* { box-sizing: border-box; }
html, body { margin: 0; min-height: 100%; background: #eef1f5; color: #101828; font-family: "SF Pro Display", "SF Pro Text", "PingFang SC", "Segoe UI", sans-serif; }
button, textarea, input, select { font: inherit; }
button, select { border: 1px solid #d0d5dd; background: #fff; color: #111827; border-radius: 12px; padding: 7px 11px; cursor: pointer; transition: background-color .16s ease, border-color .16s ease, color .16s ease, box-shadow .16s ease; }
button:hover, select:hover { background: #f8fafc; border-color: #cfd6e3; box-shadow: 0 4px 12px rgba(15, 23, 42, 0.05); }
button.primary { background: linear-gradient(135deg, #111827, #1f2937); color: #fff; border-color: #111827; }
textarea, input { width: 100%; border: 1px solid #d0d5dd; border-radius: 14px; padding: 11px 13px; background: #fff; color: #111827; }
textarea { min-height: 88px; resize: vertical; }
.shell { width: min(calc(100% - clamp(18px, 2.4vw, 34px)), 1660px); min-height: 100vh; margin: 0 auto; display: grid; grid-template-columns: minmax(12rem, 16vw) 1fr; align-items: start; background:
  radial-gradient(circle at top left, rgba(15, 23, 42, 0.06), transparent 20%),
  radial-gradient(circle at bottom right, rgba(59, 130, 246, 0.08), transparent 18%),
  linear-gradient(180deg, #f6f8fb 0%, #edf2f7 100%); }
.sidebar { position: sticky; top: 0; height: 100vh; overflow: hidden; padding: 16px 12px; border-right: 1px solid rgba(15, 23, 42, 0.08); background: rgba(248, 250, 252, 0.9); backdrop-filter: blur(18px); }
.brand { display: flex; gap: 10px; align-items: flex-start; margin-bottom: 12px; }
.brand-mark { width: 38px; height: 38px; border-radius: 13px; display: inline-flex; align-items: center; justify-content: center; color: #fff; background: linear-gradient(135deg, #111827, #334155); font-weight: 700; box-shadow: 0 12px 24px rgba(15, 23, 42, 0.14); }
.brand h2 { margin: 0 0 3px; font-size: .98rem; letter-spacing: -.03em; }
.brand p { margin: 0; color: #667085; line-height: 1.45; font-size: .84rem; }
.nav { display: grid; gap: 8px; align-content: start; }
.nav-btn { width: 100%; text-align: left; border-color: transparent; background: transparent; padding: 9px 11px; color: #344054; font-weight: 600; border-radius: 14px; }
.nav-btn.active { background: rgba(255,255,255,.95); border-color: #dbe1ea; box-shadow: 0 12px 24px rgba(15, 23, 42, 0.06); color: #101828; }
.workspace { min-width: 0; display: flex; flex-direction: column; }
.topbar { position: sticky; top: 0; z-index: 10; display: grid; grid-template-columns: minmax(0, 1fr) auto minmax(0, 1fr); gap: 12px; align-items: center; padding: 12px 18px 8px; background: rgba(246, 248, 251, 0.84); backdrop-filter: blur(18px); }
.topbar-left, .topbar-right { display: flex; align-items: center; gap: 12px; }
.topbar-right { justify-content: flex-end; }
.topbar-center { display: flex; align-items: center; justify-content: center; min-width: 0; }
.top-pair { display: inline-grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px; width: min(100%, 28rem); }
.top-meta { min-width: 0; padding: 7px 9px; border-radius: 12px; background: rgba(255,255,255,.92); border: 1px solid #e4e7ec; display: grid; gap: 2px; }
.top-meta span { font-size: .78rem; color: #667085; }
.top-meta strong { min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.status-dot { width: 10px; height: 10px; border-radius: 999px; }
.status-connected { background: #12b76a; box-shadow: 0 0 0 6px rgba(18, 183, 106, 0.12); }
.status-detected { background: #f79009; box-shadow: 0 0 0 6px rgba(247, 144, 9, 0.12); }
.status-warning { background: #f79009; box-shadow: 0 0 0 6px rgba(247, 144, 9, 0.12); }
.status-danger { background: #f04438; box-shadow: 0 0 0 6px rgba(240, 68, 56, 0.12); }
.lang-switch { display: inline-flex; border: 1px solid #d0d5dd; border-radius: 999px; padding: 3px; background: #fff; }
.lang-switch button { border: none; background: transparent; border-radius: 999px; padding: 7px 10px; }
.lang-switch button.active { background: #111827; color: #fff; }
.main { padding: 0 18px 16px; }
.chat-shell { display: grid; grid-template-columns: minmax(0, 1.94fr) minmax(15rem, 22vw); gap: 12px; align-items: start; }
.chat-main, .side-card, .action-column, .single-panel { border: 1px solid #e4e7ec; border-radius: 16px; background: rgba(255,255,255,.96); box-shadow: 0 8px 18px rgba(16, 24, 40, 0.045); }
.chat-main { padding: 12px; min-height: calc(100vh - 88px); display: flex; flex-direction: column; }
.hero-connected { background: rgba(18, 183, 106, 0.18); }
.hero-detected, .hero-warning { background: rgba(247, 144, 9, 0.18); }
.hero-danger { background: rgba(240, 68, 56, 0.18); }
.message-feed { flex: 1; overflow: auto; display: grid; gap: 9px; padding: 4px 6px 8px; }
.inline-pending { display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 9px 11px; border-radius: 13px; border: 1px solid #fecdca; background: rgba(255, 244, 242, 0.95); }
.inline-pending-copy { display: grid; gap: 2px; min-width: 0; }
.inline-pending-copy strong { font-size: .92rem; }
.inline-pending-copy span { color: #475467; font-size: .86rem; line-height: 1.4; }
.message { max-width: min(72%, 42rem); padding: 10px 12px; border-radius: 17px; border: 1px solid #e4e7ec; background: #fff; box-shadow: 0 4px 10px rgba(16,24,40,.04); content-visibility: auto; contain-intrinsic-size: 120px; }
.message-user { margin-left: auto; background: linear-gradient(180deg, #111827, #344054); color: #fff; border-color: #111827; }
.message-assistant { margin-right: auto; }
.message-pending { opacity: .88; border-style: dashed; }
.message-system { margin-right: auto; background: #f8fafc; }
.message-meta { display: flex; gap: 8px; align-items: center; margin-bottom: 7px; }
.message-role { font-size: .78rem; letter-spacing: .06em; text-transform: uppercase; color: #667085; }
.message-user .message-role { color: rgba(255,255,255,.72); }
.message-kind { font-size: .74rem; padding: 4px 8px; border-radius: 999px; background: rgba(17,24,39,.06); color: #475467; }
.message-user .message-kind { background: rgba(255,255,255,.14); color: rgba(255,255,255,.86); }
.message-text p { margin: 0 0 6px; line-height: 1.56; font-size: .93rem; }
.message-text p:last-child { margin-bottom: 0; }
.composer { margin-top: 6px; padding: 10px 6px 2px; border-top: 1px solid #eaecf0; background: linear-gradient(180deg, rgba(255,255,255,.72), rgba(255,255,255,1) 30%); }
.composer-bar { margin-top: 8px; display: flex; gap: 9px; align-items: center; justify-content: space-between; }
.composer-hint { color: #475467; font-size: .85rem; line-height: 1.4; padding: 8px 10px; border-radius: 12px; background: #f8fafc; border: 1px solid #eaecf0; flex: 1; }
.composer-foot { display: flex; justify-content: flex-end; margin-top: 8px; }
.quiet-button { border-color: transparent; background: transparent; color: #667085; padding: 6px 8px; font-size: .84rem; }
.quiet-button:hover { background: rgba(15, 23, 42, 0.05); }
.chat-side { display: grid; gap: 12px; position: sticky; top: 86px; }
.side-card, .action-column, .single-panel { padding: 12px; }
.side-head { display: flex; justify-content: space-between; gap: 12px; align-items: center; margin-bottom: 10px; }
.side-head h3 { margin: 0; font-size: .98rem; }
.approval-list, .runtime-list, .stack-view, .settings-grid { display: grid; gap: 10px; }
.action-filters { display: flex; gap: 10px; flex-wrap: wrap; }
.action-filters .filter-chip { width: auto; flex: 0 0 auto; }
.filter-chip.active { background: #111827; color: #fff; border-color: #111827; }
.card-list, .editor-col { display: grid; gap: 10px; }
.editor-row { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)) auto; gap: 8px; margin-bottom: 12px; }
.config-card { padding: 10px; border-radius: 13px; border: 1px solid #eaecf0; background: #fff; }
.toggle { display: inline-flex; gap: 8px; align-items: center; color: #475467; }
.scan-card { grid-column: 1 / -1; background:
  radial-gradient(circle at top right, rgba(59,130,246,.08), transparent 28%),
  linear-gradient(180deg, rgba(255,255,255,.98), rgba(248,250,252,.96)); }
.scan-shell { display: grid; grid-template-columns: minmax(0, 1fr); gap: 18px; align-items: center; }
.scan-copy { display: grid; gap: 10px; }
.scan-copy strong { font-size: 1rem; }
.scan-copy p { margin: 0; color: #475467; line-height: 1.55; font-size: .9rem; max-width: 52rem; }
.scan-phase-row { display: flex; gap: 10px; align-items: baseline; color: #475467; }
.scan-phase-row strong { color: #111827; font-size: .92rem; }
.scan-stage-track { height: 10px; border-radius: 999px; background: rgba(15,23,42,.08); overflow: hidden; }
.scan-stage-track span { display: block; height: 100%; border-radius: inherit; background: linear-gradient(90deg, #12b76a, #7dd3fc, #111827); transition: width .45s ease; }
.scan-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; margin-top: 16px; }
.scan-item { position: relative; width: 100%; text-align: left; padding: 0; border: 0; border-radius: 20px; background: transparent; display: block; box-shadow: none; overflow: hidden; --scan-progress: 0; --scan-progress-frac: 0; --scan-accent: #12b76a; --scan-ring: 8px; }
.scan-item-border {
  position: absolute;
  inset: 0;
  border-radius: inherit;
  padding: var(--scan-ring);
  background:
    conic-gradient(
      from -90deg,
      color-mix(in srgb, var(--scan-accent) 94%, white 6%) 0turn,
      color-mix(in srgb, var(--scan-accent) 94%, white 6%) calc(var(--scan-progress-frac) * 1turn),
      rgba(148, 163, 184, 0.24) 0turn,
      rgba(148, 163, 184, 0.14) 1turn
    );
  -webkit-mask: linear-gradient(#000 0 0) content-box, linear-gradient(#000 0 0);
  -webkit-mask-composite: xor;
  mask-composite: exclude;
  filter: saturate(1.02);
  transition: background .42s ease, filter .3s ease, transform .3s ease;
}
@keyframes scan-border-pulse {
  0%, 100% { filter: saturate(1) brightness(1); }
  50% { filter: saturate(1.12) brightness(1.07); }
}
.scan-item.running .scan-item-border { animation: scan-border-spin 2.2s linear infinite, scan-border-pulse 1.6s ease-in-out infinite; }
.scan-item-body { position: relative; margin: var(--scan-ring); padding: 14px; min-height: 138px; border-radius: 14px; background: rgba(255,255,255,.97); display: grid; gap: 12px; box-shadow: 0 12px 26px rgba(15,23,42,.06); }
.scan-item.active .scan-item-body { box-shadow: 0 14px 28px rgba(15,23,42,.09); }
.scan-item-head { display: flex; justify-content: space-between; gap: 10px; align-items: center; font-size: .88rem; }
.scan-item-head strong { font-size: .92rem; }
.scan-item-head span { color: #667085; font-size: .78rem; }
.scan-item-overview { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 10px; }
.scan-metric { padding: 10px 12px; border-radius: 12px; background: linear-gradient(180deg, rgba(248,250,252,.95), rgba(255,255,255,1)); border: 1px solid #eaecf0; display: grid; gap: 4px; }
.scan-metric label { color: #667085; font-size: .78rem; }
.scan-metric strong { font-size: 1rem; line-height: 1.1; }
.scan-item.tone-ok { --scan-accent: #12b76a; }
.scan-item.tone-warn { --scan-accent: #f79009; }
.scan-item.tone-risk { --scan-accent: #f04438; }
.scan-item.tone-ok .scan-item-body { background: linear-gradient(180deg, rgba(240, 253, 244, .88), rgba(255,255,255,.98)); }
.scan-item.tone-warn .scan-item-body { background: linear-gradient(180deg, rgba(255, 250, 235, .92), rgba(255,255,255,.98)); }
.scan-item.tone-risk .scan-item-body { background: linear-gradient(180deg, rgba(255, 241, 242, .92), rgba(255,255,255,.98)); }
.scan-detail { margin-top: 14px; padding: 14px; border-radius: 14px; border: 1px solid #eaecf0; background: rgba(255,255,255,.9); content-visibility: auto; contain-intrinsic-size: 420px; }
.scan-detail-list { display: grid; gap: 10px; }
.scan-detail-card { padding: 12px; border-radius: 12px; border: 1px solid #eaecf0; background: #fff; }
.scan-detail-card.tone-ok { border-color: rgba(18,183,106,.28); background: linear-gradient(180deg, rgba(240,253,244,.9), #fff); }
.scan-detail-card.tone-warn { border-color: rgba(247,144,9,.34); background: linear-gradient(180deg, rgba(255,250,235,.92), #fff); }
.scan-detail-card.tone-risk { border-color: rgba(240,68,56,.34); background: linear-gradient(180deg, rgba(255,241,242,.92), #fff); }
.scan-detail-head { display: flex; justify-content: space-between; gap: 10px; align-items: flex-start; margin-bottom: 8px; }
.scan-detail-title { display: grid; gap: 4px; }
.scan-detail-title span { color: #667085; font-size: .78rem; }
.scan-detail-tags { display: flex; gap: 8px; align-items: center; }
.scan-detail-card p { margin: 0 0 8px; color: #475467; line-height: 1.5; }
.scan-detail-evidence { margin-bottom: 8px; color: #667085; font-size: .82rem; background: #f8fafc; border: 1px solid #eaecf0; border-radius: 10px; padding: 8px 10px; word-break: break-word; }
.scan-detail-rec { color: #344054; font-size: .86rem; background: #f8fafc; border: 1px solid #eaecf0; border-radius: 10px; padding: 9px 10px; }
.scan-detail-rec strong { display: block; margin-bottom: 6px; }
.bulb-btn { width: auto; min-width: 0; padding: 4px 8px; border-radius: 999px; border: 1px solid #f2c94c; background: #fffbe6; }
.hook-panel { display: grid; gap: 10px; padding: 12px; border: 1px solid #eaecf0; border-radius: 14px; background: rgba(255,255,255,.92); }
.hook-panel.tone-ok { border-color: rgba(18,183,106,.28); background: linear-gradient(180deg, rgba(240,253,244,.92), #fff); }
.hook-panel.tone-warn { border-color: rgba(247,144,9,.34); background: linear-gradient(180deg, rgba(255,250,235,.94), #fff); }
.hook-panel.tone-risk { border-color: rgba(240,68,56,.34); background: linear-gradient(180deg, rgba(255,241,242,.94), #fff); }
.hook-command { display: grid; gap: 6px; }
.hook-command code { display: block; white-space: pre-wrap; word-break: break-word; padding: 9px 10px; border-radius: 10px; background: rgba(15,23,42,.04); border: 1px solid rgba(15,23,42,.08); color: #344054; font-size: .82rem; }
.hook-detail { color: #475467; font-size: .84rem; line-height: 1.55; }
.approval-card { padding: 10px; border-radius: 13px; border: 1px solid #eaecf0; background: #fff; content-visibility: auto; contain-intrinsic-size: 220px; }
.tone-safe { background: #f8fafc; }
.tone-caution { background: #fffaf0; border-color: #fedf89; }
.tone-dangerous { background: #fff7ed; border-color: #fdba74; }
.tone-blocked { background: #fff4f2; border-color: #fecdca; }
.approval-head, .approval-actions { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
.approval-head { margin-bottom: 8px; }
.approval-card h4 { margin: 0 0 4px; font-size: .92rem; }
.approval-request { margin: 0 0 6px; font-size: .83rem; color: #667085; line-height: 1.45; }
.approval-card p { margin: 0 0 6px; color: #475467; line-height: 1.4; font-size: .88rem; }
.approval-meta { color: #667085; font-size: .84rem; margin-bottom: 8px; }
.risk-chip, .status-chip { display: inline-flex; align-items: center; padding: 4px 9px; border-radius: 999px; font-size: .8rem; }
.risk-chip { background: rgba(17,24,39,.06); color: #344054; }
.status-chip { background: #f2f4f7; color: #475467; }
.execution-note { margin: 0 0 8px; padding: 8px 10px; border-radius: 11px; background: #f8fafc; border: 1px solid #eaecf0; color: #475467; font-size: .86rem; line-height: 1.45; }
.confirm-input { flex: 1; min-width: 160px; }
.approval-actions button { width: auto; flex: 0 0 auto; }
.runtime-list div { display: grid; gap: 4px; padding: 9px; border-radius: 11px; border: 1px solid #eaecf0; background: #fff; }
.runtime-list .runtime-inline { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px; padding: 0; border: 0; background: transparent; }
.runtime-list .runtime-inline > div { min-width: 0; }
.runtime-list span { color: #667085; font-size: .85rem; }
.placeholder-card, .setting-copy, .empty { color: #667085; }
.stack-view { grid-template-columns: minmax(0, 1fr); }
.action-column { background: rgba(255,255,255,.92); max-width: min(100%, 64rem); }
.settings-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
.settings-actions { display: flex; gap: 10px; flex-wrap: wrap; margin-top: 12px; }
.pager { display: flex; justify-content: space-between; align-items: center; gap: 12px; padding-top: 8px; }
.pager-info { color: #667085; font-size: .9rem; }
.page-footer { display: grid; grid-template-columns: 1fr auto 1fr; align-items: center; margin-top: 18px; padding: 16px 6px 8px; color: #667085; font-size: .9rem; }
.footer-center { grid-column: 2; justify-self: center; }
.footer-right { grid-column: 3; justify-self: end; }
.toast { position: fixed; right: 20px; bottom: 20px; max-width: 420px; padding: 12px 14px; border-radius: 16px; background: rgba(15, 23, 42, 0.94); color: #fff; box-shadow: 0 18px 42px rgba(15,23,42,.24); z-index: 50; }
pre { white-space: pre-wrap; word-break: break-word; background: #0f172a; color: #e2e8f0; border-radius: 12px; padding: 12px; overflow: auto; max-height: 280px; font-size: .85rem; }
details summary { cursor: pointer; color: #344054; }
@keyframes scan-border-spin {
  from { transform: rotate(0deg); }
  to { transform: rotate(360deg); }
}
@media (max-width: 1180px) {
  .shell { grid-template-columns: 1fr; }
  .sidebar { border-right: 0; border-bottom: 1px solid rgba(15, 23, 42, 0.08); }
  .topbar { grid-template-columns: 1fr; }
  .topbar-center, .topbar-right { justify-content: flex-start; }
  .chat-shell, .stack-view, .settings-grid { grid-template-columns: 1fr; }
  .editor-row { grid-template-columns: 1fr; }
  .chat-side { position: static; }
  .chat-main { min-height: 0; }
  .scan-grid { grid-template-columns: 1fr 1fr; }
}
@media (max-width: 720px) {
  .topbar, .main { padding-left: 16px; padding-right: 16px; }
  .composer-bar, .approval-actions { flex-direction: column; align-items: stretch; }
  .inline-pending { flex-direction: column; align-items: stretch; }
  .message { max-width: 100%; }
  .top-pair, .runtime-list .runtime-inline { grid-template-columns: 1fr; }
  .scan-item-overview { grid-template-columns: 1fr; }
  .page-footer { grid-template-columns: 1fr; gap: 6px; }
  .footer-center, .footer-right { grid-column: auto; justify-self: center; }
}
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after { animation: none !important; transition: none !important; scroll-behavior: auto !important; }
}
"""
