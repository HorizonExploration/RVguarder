async function fetchSummary() {
  try {
    const res = await fetch("/api/summary");
    if (!res.ok) return {};
    return await res.json();
  } catch (_) {
    return {};
  }
}

const INITIAL_SUMMARY = await fetchSummary();

const state = {
  summary: INITIAL_SUMMARY || {},
  view: "dashboard",
  actionFilter: "pending_approval",
  pages: { actions: 1 },
  pageSize: 8,
  toast: null,
  scan: { running: false, progress: 0, phase: "", result: null, selected: "config" },
};

const T = {
  appName: "龙虾卫士",
  appSub: "OpenClaw 安全插件",
  dashboard: "概览",
  actions: "动作审批",
  settings: "安全扫描",
  connected: "已连接",
  disconnected: "未连接",
  refresh: "刷新",
  openOpenClaw: "前往 OpenClaw 继续对话",
  pendingTitle: "待确认动作",
  noPending: "当前没有待确认动作。",
  recentActions: "最近动作",
  noActions: "还没有动作记录。",
  approve: "确认继续",
  reject: "拒绝",
  approving: "正在确认…",
  rejecting: "正在拒绝…",
  details: "查看详情",
  status_pending_approval: "待确认",
  status_blocked: "已拦截",
  status_executed: "已执行",
  status_failed: "失败",
  scanTitle: "基线扫描",
  scanStart: "开始扫描",
  scanRunning: "正在扫描中…",
  scanFinished: "扫描完成",
  scanIdle: "准备开始基线扫描",
  scanHint: "会检查配置、端口、依赖、运行用户和审计项。",
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
  audit: "审计导出",
  prevPage: "上一页",
  nextPage: "下一页",
  pageInfo: "第 {current} / {total} 页",
  hookTitle: "运行时拦截状态",
  hookActive: "已接入 OpenClaw 工具拦截链",
  hookInactive: "还没有接入 OpenClaw 工具拦截链",
  hookRestart: "需要重启 OpenClaw gateway 后才会生效。",
  error_default: "请求处理失败，请稍后重试。",
};

function t(key) { return T[key] || key; }

function escapeHtml(value) {
  return String(value ?? "").replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;");
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
  const root = document.getElementById("toast-root");
  if (root) root.innerHTML = `<div class="toast">${escapeHtml(message)}</div>`;
  clearTimeout(window.__guardToastTimer);
  window.__guardToastTimer = setTimeout(() => { state.toast = null; if (root) root.innerHTML = ""; }, 2800);
}

function setView(view) { state.view = view; render(); }

function paginate(items, pageKey) {
  const total = Math.max(1, Math.ceil(items.length / state.pageSize));
  const current = Math.min(Math.max(state.pages[pageKey] || 1, 1), total);
  state.pages[pageKey] = current;
  const start = (current - 1) * state.pageSize;
  return { items: items.slice(start, start + state.pageSize), current, total };
}

function renderPager(pageKey, current, total) {
  if (total <= 1) return "";
  return `<div class="pager">
    <button class="pager-btn" data-page-key="${escapeHtml(pageKey)}" data-page-next="0" ${current <= 1 ? "disabled" : ""}>${t("prevPage")}</button>
    <span class="pager-info">${t("pageInfo").replace("{current}", current).replace("{total}", total)}</span>
    <button class="pager-btn" data-page-key="${escapeHtml(pageKey)}" data-page-next="1" ${current >= total ? "disabled" : ""}>${t("nextPage")}</button>
  </div>`;
}

// ----------------------------------------------------------------
//  Dashboard
// ----------------------------------------------------------------

function renderDashboard() {
  const items = (state.summary.actions || {}).items || [];
  const pending = items.filter(item => item.status === "pending_approval");
  const recent = items.slice(0, 6);
  const hook = state.summary.hook || {};
  const chat = state.summary.chat || {};
  const connected = (chat.connection_state || "disconnected") === "connected";
  return `<div class="dashboard">
    <section class="hero-card ${connected ? "connected" : "disconnected"}">
      <div class="hero-status">
        <span class="status-dot status-${connected ? "connected" : "danger"}"></span>
        <strong>${t(connected ? "connected" : "disconnected")}</strong>
      </div>
      <p>${t("openOpenClaw")}</p>
      ${connected ? `<p class="hero-model">模型：${escapeHtml(chat.current_model || "—")} · Agent：${escapeHtml(chat.current_agent || "—")}</p>` : ""}
    </section>
    <section class="side-card">
      <div class="side-head"><h3>${t("pendingTitle")} (${pending.length})</h3></div>
      <div class="approval-list">${pending.length ? pending.map(renderPendingCard).join("") : `<div class="empty">${t("noPending")}</div>`}</div>
    </section>
    <section class="side-card">
      <div class="side-head"><h3>${t("recentActions")}</h3></div>
      <div class="approval-list">${recent.length ? recent.map(renderPendingCard).join("") : `<div class="empty">${t("noActions")}</div>`}</div>
    </section>
    <section class="side-card">
      <div class="side-head"><h3>${t("hookTitle")}</h3></div>
      <div class="hook-status">${hook.active ? `<span class="badge ok">${t("hookActive")}</span>` : `<span class="badge warn">${t("hookInactive")}</span> ${hook.restart_required ? t("hookRestart") : ""}`}</div>
    </section>
  </div>`;
}

// ----------------------------------------------------------------
//  Actions
// ----------------------------------------------------------------

function renderActionsView() {
  const items = (state.summary.actions || {}).items || [];
  const filtered = items.filter(item => item.status === state.actionFilter);
  const page = paginate(filtered, "actions");
  return `<div class="stack-view">
    <div class="action-filters">
      ${["pending_approval", "blocked", "executed", "failed"].map(s => `<button class="filter-chip ${state.actionFilter === s ? "active" : ""}" data-action-filter="${s}">${t("status_" + s)}</button>`).join("")}
    </div>
    <div class="approval-list">${page.items.length ? page.items.map(renderPendingCard).join("") : `<div class="empty">${t("noActions")}</div>`}</div>
    ${renderPager("actions", page.current, page.total)}
  </div>`;
}

// ----------------------------------------------------------------
//  Settings — 完整基线扫描面板
// ----------------------------------------------------------------

function scanCards() {
  const baseline = state.summary.baseline || {};
  const checks = baseline.checks && baseline.checks.length
    ? baseline.checks
    : baseline.findings
      ? baseline.findings.map((f, i) => ({
          check_id: f.finding_id || `f-${i}`,
          category: f.category || "audit",
          title: f.title || "",
          status: f.severity === "critical" || f.severity === "high" ? "risk" : "warn",
          severity: f.severity || "medium",
          description: f.description || "",
          recommendation: f.recommendation || "",
          evidence: f.evidence || {},
        }))
      : [];
  const groups = {
    config: { key: "config", title: t("scanCategory_config"), checks: checks.filter(c => c.category === "config") },
    runtime: { key: "runtime", title: t("scanCategory_runtime"), checks: checks.filter(c => ["runtime","network","os"].includes(c.category)) },
    dependency: { key: "dependency", title: t("scanCategory_dependency"), checks: checks.filter(c => c.category === "dependency") },
    audit: { key: "audit", title: t("scanCategory_audit"), checks },
  };
  return Object.values(groups).map(g => {
    const riskCount = g.checks.filter(c => c.status === "risk").length;
    const warnCount = g.checks.filter(c => c.status === "warn").length;
    const tone = riskCount > 0 ? "risk" : warnCount > 0 ? "warn" : "ok";
    return { ...g, tone, count: riskCount + warnCount, totalChecks: g.checks.length };
  });
}

function selectedScanCard() {
  const cards = scanCards();
  return cards.find(c => c.key === state.scan.selected) || cards[0];
}

function renderSettingsView() {
  const cards = scanCards();
  const selected = selectedScanCard();
  const scanProgress = Math.max(0, Math.min(100, Number(state.scan.progress || 0)));
  return `<div class="settings-grid">
    <article class="side-card scan-card ${state.scan.running ? "scan-running" : ""}">
      <div class="side-head"><h3>${t("scanTitle")}</h3></div>
      <div class="scan-shell">
        <div class="scan-copy">
          <strong>${state.scan.running ? t("scanRunning") : state.scan.result ? t("scanFinished") : t("scanIdle")}</strong>
          <p>${t("scanHint")}</p>
          <div class="scan-phase-row">
            <span>${t("scanProgress")}</span>
            <strong>${t(state.scan.phase || "scanStage_prepare")}</strong>
          </div>
          <div class="scan-stage-track"><span style="width:${scanProgress}%"></span></div>
          <div class="settings-actions">
            <button id="run-baseline" class="primary" ${state.scan.running ? "disabled" : ""}>${state.scan.running ? t("scanRunning") : t("scanStart")}</button>
            <button id="export-audit">${t("audit")}</button>
          </div>
        </div>
      </div>
      <div class="scan-grid">
        ${cards.map(card => `<button class="scan-item tone-${card.tone} ${state.scan.selected === card.key ? "active" : ""} ${state.scan.running && state.scan.selected === card.key ? "running" : ""}" data-scan-key="${card.key}">
          <div class="scan-item-body">
            <div class="scan-item-head">
              <strong>${escapeHtml(card.title)}</strong>
              <span>${card.tone === "risk" ? t("scanStatus_risk") : card.tone === "warn" ? t("scanStatus_warn") : t("scanStatus_ok")}</span>
            </div>
            <div class="scan-item-overview">
              <div class="scan-metric"><label>${t("scanIssues")}</label><strong>${card.count}</strong></div>
              <div class="scan-metric"><label>${t("scanChecks")}</label><strong>${card.totalChecks}</strong></div>
            </div>
          </div>
        </button>`).join("")}
      </div>
      <div class="scan-detail">
        <div class="side-head">
          <h3>${escapeHtml(selected?.title || t("scanDetails"))}</h3>
          <span class="status-chip">${selected?.tone === "risk" ? t("scanStatus_risk") : selected?.tone === "warn" ? t("scanStatus_warn") : t("scanStatus_ok")}</span>
        </div>
        <div class="scan-detail-list">
          ${(selected?.checks || []).length ? selected.checks.map(item => `<article class="scan-detail-card tone-${item.status || "ok"}">
            <div class="scan-detail-head">
              <div class="scan-detail-title">
                <strong>${escapeHtml(item.title || "")}</strong>
                <span>${escapeHtml(item.check_id || "")}</span>
              </div>
              <span class="risk-chip">${item.status === "ok" ? t("scanStatus_ok") : item.status === "warn" ? t("scanStatus_warn") : t("scanStatus_risk")}</span>
            </div>
            <p>${escapeHtml(item.description || "")}</p>
            ${item.evidence && Object.keys(item.evidence).length ? `<div class="scan-detail-evidence">${escapeHtml(JSON.stringify(item.evidence))}</div>` : ""}
            ${item.recommendation ? `<div class="scan-detail-rec"><strong>修改建议</strong><div>${escapeHtml(item.recommendation)}</div></div>` : ""}
          </article>`).join("") : `<div class="empty">${t("noActions")}</div>`}
        </div>
      </div>
    </article>
  </div>`;
}

// ----------------------------------------------------------------
//  Shared components
// ----------------------------------------------------------------

function renderPendingCard(item) {
  const decision = item.decision || {};
  const isPending = item.status === "pending_approval";
  const isLoading = item._loading;
  return `<article class="approval-card tone-${escapeHtml(decision.risk_level || "safe")} ${isLoading ? "card-loading" : ""}">
    <div class="approval-head">
      <span class="risk-chip">${escapeHtml(decision.risk_level || "safe")}</span>
      <span class="status-chip">${t("status_" + (item.status || "unknown"))}</span>
    </div>
    <h4>${escapeHtml(item.target_summary || item.source_message || "")}</h4>
    <p>${escapeHtml(decision.reason || "")}</p>
    ${isPending ? `<div class="approval-actions">
      <button class="primary approve-action" data-id="${escapeHtml(item.action_id)}" ${isLoading ? "disabled" : ""}>${isLoading ? t("approving") : t("approve")}</button>
      <button class="reject-action" data-id="${escapeHtml(item.action_id)}" ${isLoading ? "disabled" : ""}>${isLoading ? t("rejecting") : t("reject")}</button>
    </div>` : ""}
    <details><summary>${t("details")}</summary><pre>${escapeHtml(JSON.stringify(item, null, 2))}</pre></details>
  </article>`;
}

// ----------------------------------------------------------------
//  Main render
// ----------------------------------------------------------------

function render() {
  const root = document.getElementById("app");
  root.innerHTML = `<div class="shell">
    <aside class="sidebar">
      <div class="brand"><h2>${t("appName")}</h2><p>${t("appSub")}</p></div>
      <nav>${["dashboard","actions","settings"].map(v => `<button class="nav-btn ${state.view === v ? "active" : ""}" data-view="${v}">${t(v)}</button>`).join("")}</nav>
    </aside>
    <main class="main">
      <div class="topbar">
        <button id="refresh-button">${t("refresh")}</button>
      </div>
      <div class="content">${state.view === "actions" ? renderActionsView() : state.view === "settings" ? renderSettingsView() : renderDashboard()}</div>
    </main>
    <div id="toast-root"></div>
  </div>`;
  bind();
}

function bind() {
  document.querySelectorAll(".nav-btn").forEach(b => { b.onclick = () => setView(b.dataset.view); });
  document.getElementById("refresh-button").onclick = () => refreshAll();
  document.querySelectorAll(".approve-action").forEach(b => { b.onclick = () => approveAction(b.dataset.id); });
  document.querySelectorAll(".reject-action").forEach(b => { b.onclick = () => rejectAction(b.dataset.id); });
  document.querySelectorAll(".filter-chip").forEach(b => { b.onclick = () => { state.actionFilter = b.dataset.actionFilter; state.pages.actions = 1; render(); }; });
  document.querySelectorAll(".pager-btn").forEach(b => { b.onclick = () => setPage(b.dataset.pageKey, b.dataset.pageNext === "1" ? 1 : -1); });
  const runBtn = document.getElementById("run-baseline");
  if (runBtn) runBtn.onclick = () => runBaseline();
  const exportBtn = document.getElementById("export-audit");
  if (exportBtn) exportBtn.onclick = () => exportAudit();
  document.querySelectorAll(".scan-item").forEach(b => { b.onclick = () => { state.scan.selected = b.dataset.scanKey; render(); }; });
}

function setPage(pageKey, next) {
  state.pages[pageKey] = Math.max(1, (state.pages[pageKey] || 1) + next);
  render();
}

// ----------------------------------------------------------------
//  Data fetching
// ----------------------------------------------------------------

async function refreshAll() {
  try {
    const summary = await api("/api/summary");
    state.summary = summary;
    render();
  } catch (error) {
    toast(error.payload?.message || t("error_default"));
  }
}

// ----------------------------------------------------------------
//  Actions — 乐观更新，审批后卡片立即消失
// ----------------------------------------------------------------

function _optimisticUpdate(actionId, newStatus) {
  const actions = state.summary.actions || {};
  const items = (actions.items || []).map(item =>
    item.action_id === actionId ? { ...item, status: newStatus } : item
  );
  state.summary = { ...state.summary, actions: { ...actions, items } };
}

function _setActionLoading(actionId, loading) {
  const actions = state.summary.actions || {};
  const items = (actions.items || []).map(item =>
    item.action_id === actionId ? { ...item, _loading: loading } : item
  );
  state.summary = { ...state.summary, actions: { ...actions, items } };
}

async function approveAction(actionId) {
  // 乐观更新：先把按钮置为 loading + 立即重渲染
  _setActionLoading(actionId, true);
  render();
  try {
    await api("/api/actions/approve", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ action_id: actionId, confirmation_text: "" }) });
    // 乐观更新：立即标记为已批准，卡片从待确认列表消失
    _optimisticUpdate(actionId, "approved");
    toast("已批准");
    render();
    // 后台静默刷新
    await refreshAll();
  } catch (error) {
    _setActionLoading(actionId, false);
    render();
    toast(error.payload?.message || t("error_default"));
  }
}

async function rejectAction(actionId) {
  _setActionLoading(actionId, true);
  render();
  try {
    await api("/api/actions/reject", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ action_id: actionId }) });
    _optimisticUpdate(actionId, "rejected");
    toast("已拒绝");
    render();
    await refreshAll();
  } catch (error) {
    _setActionLoading(actionId, false);
    render();
    toast(error.payload?.message || t("error_default"));
  }
}

// ----------------------------------------------------------------
//  Scan / Audit
// ----------------------------------------------------------------

async function runBaseline() {
  const phases = ["scanStage_prepare", "scanStage_config", "scanStage_runtime", "scanStage_audit"];
  const progressSteps = [18, 42, 71, 92];
  let phaseIndex = 0;
  state.scan = { running: true, progress: progressSteps[0], phase: phases[0], result: null, selected: "config" };
  render();
  const timer = setInterval(() => {
    phaseIndex = Math.min(phaseIndex + 1, phases.length - 1);
    state.scan.phase = phases[phaseIndex];
    state.scan.progress = progressSteps[phaseIndex];
    render();
  }, 520);
  try {
    const payload = await api("/api/baseline/run", { method: "POST" });
    clearInterval(timer);
    state.scan = { running: false, progress: 100, phase: "scanStage_audit", result: payload, selected: "config" };
    toast(t("scanFinished"));
    render();
    await refreshAll();
  } catch (error) {
    clearInterval(timer);
    state.scan.running = false;
    toast(error.payload?.message || t("error_default"));
    render();
  }
}

async function exportAudit() {
  try {
    const payload = await api("/api/audit/export", { method: "POST" });
    toast(`导出成功：${payload.json}`);
  } catch (error) {
    toast(error.payload?.message || t("error_default"));
  }
}

render();
