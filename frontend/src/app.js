async function fetchSummary() {
  try { const r = await fetch("/api/summary"); if (!r.ok) return {}; return await r.json(); }
  catch (_) { return {}; }
}

const state = {
  summary: {},
  view: "dashboard",
  actionFilter: "pending_approval",
  pages: { actions: 1 },
  pageSize: 8,
  toast: null,
  scan: { running: false, progress: 0, phase: "", result: null, selected: "config" },
  rulesSearch: "",
  loading: true,
  _pollTimer: null,
  _summaryHash: "",
  _userScrolling: false,
  rvMode: (localStorage.getItem("openclaw-guard-rv-mode") || "on") === "on",
};

const T = {
  appName: "龙虾卫士", appSub: "OpenClaw 安全插件",
  dashboard: "概览", actions: "动作审批", rules: "安全规则", settings: "安全扫描", skills: "技能管理",
  connected: "已连接", disconnected: "未连接", openOpenClaw: "前往 OpenClaw 继续对话",
  approve: "确认继续", reject: "拒绝", approving: "正在确认…", rejecting: "正在拒绝…",
  details: "查看详情",
  status_pending_approval: "待确认", status_blocked: "已拦截", status_executed: "已执行", status_failed: "失败",
  status_allow: "安全放行", status_proposed: "待处理", status_rejected: "已拒绝", status_approved: "已批准", status_executing: "执行中",
  pendingTitle: "待确认动作", noPending: "当前没有待确认动作。",
  recentActions: "最近动作", noActions: "还没有动作记录。",
  scanTitle: "基线扫描", scanStart: "开始扫描", scanRunning: "正在扫描中…", scanFinished: "扫描完成",
  scanIdle: "准备开始基线扫描",
  scanHint: "会检查配置、端口、依赖、运行用户和审计项。",
  scanProgress: "当前阶段",
  scanStage_prepare: "准备扫描环境", scanStage_config: "检查配置与权限",
  scanStage_runtime: "核对运行状态与开放端口", scanStage_audit: "整理报告与整改建议",
  scanCategory_config: "配置与权限", scanCategory_runtime: "运行环境",
  scanCategory_dependency: "依赖与源代码", scanCategory_audit: "审计与资产",
  scanIssues: "问题", scanAssets: "资产", scanChecks: "检查项", scanDetails: "详细说明",
  scanStatus_ok: "正常", scanStatus_warn: "需留意", scanStatus_risk: "存在风险",
  prevPage: "上一页", nextPage: "下一页", pageInfo: "第 {current} / {total} 页",
  hookTitle: "运行时拦截状态",
  hookActive: "已接入 OpenClaw 工具拦截链",
  hookInactive: "还没有接入 OpenClaw 工具拦截链",
  hookRestart: "需要重启 OpenClaw gateway 后才会生效。",
  auditExport: "导出审计 JSON",
  clear: "清空",
  rulesTitle: "安全规则管理", rulesSearch: "搜索规则…", rulesTotal: "条规则",
  traceTitle: "安全执行链路", traceNoData: "暂无动作记录",
  loadingText: "正在加载…", error_default: "请求处理失败",
  refresh: "刷新",
  rvMode: "RV 模式",
  rvModeOn: "开启",
  rvModeOff: "关闭",
  skillsTitle: "技能管理",
  skillsEmpty: "当前没有可管理的 skill 配置。",
};
function t(k) { return T[k] || k; }

const SCENE_ZH = {
  mail_send: "📧 邮件发送", mail_read: "📬 邮件读取", report_send: "📋 日报外发",
  report_generate: "📝 日报生成", attachment_download: "📎 附件下载",
  file_delete: "🗑️ 文件删除", file_write: "✏️ 文件写入", config_modify: "⚙️ 配置修改",
  network_egress: "🌐 网络外联", channel_send: "📨 渠道发送", skill_run: "🔧 技能执行",
  command_exec: "💻 命令执行", chat_message: "💬 对话",
};
function sceneZh(s) { return SCENE_ZH[s] || s.replace(/_/g, " "); }

const STATUS_ZH = {
  pending_approval: "⏳ 待确认", blocked: "🚫 已拦截", executed: "✅ 已执行",
  executing: "🔄 执行中", failed: "❌ 失败", rejected: "🚫 已拒绝",
  approved: "✅ 已批准", proposed: "📋 待处理", allow: "✅ 已放行", ask: "⚠️ 需审批",
};

function esc(v) { return String(v ?? "").replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;").replaceAll('"',"&quot;"); }

function _setRvMode(on) {
  state.rvMode = !!on;
  localStorage.setItem("openclaw-guard-rv-mode", state.rvMode ? "on" : "off");
}

/* ── API & Toast ─────────────────────── */
async function api(p, opts = {}) {
  const r = await fetch(p, opts); const pl = await r.json().catch(() => ({}));
  if (!r.ok) { const e = new Error(pl.error_code || pl.error || "request_failed"); e.payload = pl; throw e; }
  return pl;
}
function toast(msg) {
  state.toast = msg; const root = document.getElementById("toast-root");
  if (root) root.innerHTML = '<div class="toast">' + esc(msg) + '</div>';
  clearTimeout(window.__guardToastTimer);
  window.__guardToastTimer = setTimeout(() => { state.toast = null; if (root) root.innerHTML = ""; }, 3000);
}

/* ── Polling (带 hash 对比，仅数据变化时渲染) ── */
function _hash(o) { return o ? JSON.stringify(o).length + "_" + ((o.items||[]).length) : "0"; }
function startPolling() {
  stopPolling();
  state._pollTimer = setInterval(async () => {
    try {
      const s = await api("/api/summary");
      const h = _hash(s.actions);
      if (h !== state._summaryHash || state.loading) {
        state.summary = s; state.loading = false; state._summaryHash = h; render();
      }
    } catch (_) {}
  }, 1500);
}
function stopPolling() { if (state._pollTimer) { clearInterval(state._pollTimer); state._pollTimer = null; } }

/* ── Views / Pagination ──────────────── */
function setView(v) { state.view = v; render(); if (v === "dashboard") startPolling(); else stopPolling(); }

function paginate(items, pk) {
  const total = Math.max(1, Math.ceil(items.length / state.pageSize));
  const cur = Math.min(Math.max(state.pages[pk] || 1, 1), total);
  state.pages[pk] = cur;
  return { items: items.slice((cur - 1) * state.pageSize, cur * state.pageSize), current: cur, total };
}
function renderPager(pk, cur, total) {
  if (total <= 1) return "";
  return '<div class="pager"><button class="pager-btn" data-key="' + pk + '" data-n="0"' + (cur<=1?" disabled":"") + '>' + t("prevPage") + '</button><span class="pager-info">' + t("pageInfo").replace("{current}",cur).replace("{total}",total) + '</span><button class="pager-btn" data-key="' + pk + '" data-n="1"' + (cur>=total?" disabled":"") + '>' + t("nextPage") + '</button></div>';
}

/* ── Dashboard（完整功能） ────────────── */
function renderDashboard() {
  const items = (state.summary.actions || {}).items || [];
  const pending = items.filter(i => i.status === "pending_approval");
  const chat = state.summary.chat || {};
  const hook = state.summary.hook || {};
  const connected = (chat.connection_state || "disconnected") === "connected";
  if (state.loading && !items.length) return '<div class="loading-wrap"><div class="loading-spinner"></div><p>' + t("loadingText") + '</p></div>';
  return '<div class="dashboard">'
    + _heroCard(connected, chat)
    + _statsRow(items, pending)
    + (state.rvMode ? _liveTrace(items) : "")
    + _pendingSection(pending)
    + _recentSection(items)
    + _hookSection(hook)
    + '</div>';
}
function _heroCard(connected, chat) {
  const target = state.summary.target || {};
  const openClawUrl = (target.web_urls && target.web_urls.length) ? target.web_urls[0] : "http://localhost:8000";
  return '<section class="card hero-card' + (connected?" connected":"") + '">'
    + '<div class="hero-main">'
    + '<div class="hero-status"><span class="status-dot ' + (connected?"green":"red") + '"></span><strong>' + t(connected?"connected":"disconnected") + '</strong></div>'
    + '<div class="hero-action">'
    + '<p>' + t("openOpenClaw") + '</p>'
    + '<a href="' + openClawUrl + '" target="_blank" class="btn primary hero-btn">立即前往</a>'
    + '</div>'
    + '</div>'
    + (connected?'<div class="hero-meta"><span>模型：' + esc(chat.current_model||"—") + '</span><span>Agent：' + esc(chat.current_agent||"—") + '</span></div>':"")
    + '</section>';
}
function _statsRow(items, pending) {
  const counts = (state.summary.actions || {}).counts || {};
  const b = counts.blocked || 0, r = counts.rejected || 0, e = counts.executed || 0;
  const total = counts.total || items.length;
  return '<div class="stats-row"><div class="stat-card"><div class="stat-value" style="color:#f04438">' + (counts.pending || 0) + '</div><div class="stat-label">待确认</div></div><div class="stat-card"><div class="stat-value" style="color:#f79009">' + (b + r) + '</div><div class="stat-label">已拦截</div></div><div class="stat-card"><div class="stat-value" style="color:#12b76a">' + e + '</div><div class="stat-label">已执行</div></div><div class="stat-card"><div class="stat-value">' + total + '</div><div class="stat-label">总动作</div></div></div>';
}
function _pendingSection(pending) {
  return '<section class="card"><div class="card-head"><h3>' + t("pendingTitle") + ' (' + pending.length + ')</h3></div><div class="approval-list">' + (pending.length?pending.map(renderPendingCard).join(""):'<div class="empty">' + t("noPending") + '</div>') + '</div></section>';
}
function _recentSection(items) {
  const recent = items.slice(0, 6);
  return '<section class="card"><div class="card-head"><h3>' + t("recentActions") + '</h3>'
    + (items.length ? '<button class="btn-text danger" id="clear-actions">' + t("clear") + '</button>' : '')
    + '</div><div class="approval-list">' + (recent.length?recent.map(renderPendingCard).join(""):'<div class="empty">' + t("noActions") + '</div>') + '</div></section>';
}
function _hookSection(hook) {
  const st = hook.state || "unknown";
  let badge = '<span class="badge warn">' + t("hookInactive") + '</span>';
  if (hook.active && st === "active") {
    badge = '<span class="badge ok">' + t("hookActive") + '</span>';
  } else if (st === "loaded_waiting_restart") {
    badge = '<span class="badge warn">⏳ 已配置，需重启 Gateway</span>';
  } else if (st === "runtime_unreachable") {
    badge = '<span class="badge warn">⚠️ OpenClaw Gateway 未连接</span>';
  } else if (st === "plugin_invalid") {
    badge = '<span class="badge danger">❌ 插件文件异常</span>';
  }
  const detail = hook.error_detail ? '<p class="hook-detail">' + esc(hook.error_detail) + '</p>' : "";
  const hint = hook.runtime_hint ? '<p class="hook-hint">' + esc(hook.runtime_hint) + '</p>' : "";
  return '<section class="card"><div class="card-head"><h3>' + t("hookTitle") + '</h3></div><div class="hook-status">' + badge + detail + hint + '</div></section>';
}

/* ── Live Trace Timeline（修复状态 + 滚动） ── */
let _traceScrollTop = 0;
function _liveTrace(items) {
  const trace = items.slice(0, 10);
  let html = '<section class="card trace-card"><div class="card-head"><h3><span class="trace-dot"></span> ' + t("traceTitle") + '</h3><span class="badge info">实时</span></div>';
  if (!trace.length) { html += '<div class="timeline-empty">' + t("traceNoData") + '</div></section>'; return html; }
  html += '<div class="timeline-scroll" id="timeline-scroll"><div class="timeline">';
  for (const item of trace) {
    const st = item.status || "pending_approval";
    const dec = item.decision || {};
    const em = (item.event || {}).metadata || {};
    const sem = em.semantic || {};
    const rv = em.rv_result || {};
    const timings = em.pipeline_timings_ms || {};
    const sc = sem.scenario || item.event?.action_type || "unknown";
    const labels = sem.labels || [];
    const rsn = dec.reason || item.target_summary || "";
    const sta = STATUS_ZH[st] || st;
    // 状态判定：优先用 item.status，再 fallback 到 dec.action
    const isRunning = st === "executing";
    const isPending = st === "pending_approval";
    const isDone = st === "executed" || st === "approved" || st === "allow";
    const isBad = st === "blocked" || st === "rejected" || st === "failed" || st === "denied";
    const isWarning = st === "ask" || st === "escalate";
    let cls = "tl-step-wrap";
    if (isRunning) cls += " running";
    else if (isPending) cls += " pending";
    else if (isBad) cls += " blocked";
    else if (isWarning) cls += " warn";
    else cls += " done";

    let icon = "✅";
    if (isRunning) icon = "🔄"; else if (isPending) icon = "⏳"; else if (isBad) icon = "🚫"; else if (isWarning) icon = "⚠️";

    html += '<div class="' + cls + '">';
    html += '<div class="tl-step"><div class="tl-head"><span class="tl-icon">' + icon + '</span><span class="tl-scene">' + esc(sceneZh(sc)) + '</span><span class="tl-status ' + st + '">' + sta + '</span></div>';
    html += '<div class="tl-time">' + esc((item.created_at||"").slice(0,19).replace("T"," ")) + '</div>';
    if (rsn) html += '<div class="tl-reason">' + esc(rsn) + '</div>';
    if (timings && Object.keys(timings).length) {
      const s = (k, label) => (timings[k] !== undefined ? '<span class="tl-chip">' + label + ' ' + esc(timings[k]) + 'ms</span>' : "");
      html += '<div class="tl-chips">' + s("semantic_ms", "语义") + s("detection_ms", "检测") + s("rv_ms", "RV") + s("controller_ms", "决策") + s("total_ms", "总耗时") + '</div>';
    }
    if (rv && rv.verdict) {
      const tone = rv.verdict === "ok" ? "ok" : rv.verdict === "ask" ? "warn" : rv.verdict === "escalate" ? "warn" : "danger";
      html += '<div class="tl-rv">'
        + '<div class="tl-rv-head">'
        + '<span class="badge ' + tone + '">运行时验证 (RV): ' + esc(rv.verdict.toUpperCase()) + '</span>'
        + (rv.window_size !== undefined ? '<span class="tl-rv-win">窗口: ' + esc(rv.window_size) + '</span>' : '')
        + '</div>'
        + '<div class="tl-rv-body">'
        + (rv.triggered_by ? '<div><strong>触发监视器:</strong> ' + esc(rv.triggered_by) + '</div>' : "")
        + (rv.reason ? '<div><strong>判定依据:</strong> ' + esc(rv.reason) + '</div>' : "")
        + '</div>'
        + '</div>';
    }
    if (labels.length) html += '<div class="tl-tags">' + labels.slice(0,5).map(l=>'<span class="tl-tag">' + esc(l) + '</span>').join("") + '</div>';
    html += '<details><summary>' + t("details") + '</summary><pre>' + esc(JSON.stringify(item,null,2)) + '</pre></details>';
    html += '</div></div>';
  }
  html += '</div></div></section>';
  return html;
}

/* ── Actions ─────────────────────────── */
function renderActionsView() {
  const items = (state.summary.actions || {}).items || [];
  const filtered = items.filter(i => i.status === state.actionFilter);
  const page = paginate(filtered, "actions");
  return '<div class="stack-view"><div class="action-filters">' + ["pending_approval","approved","executing","executed","rejected","blocked","failed"].map(s => '<button class="filter-chip' + (state.actionFilter===s?" active":"") + '" data-f="' + s + '">' + t("status_"+s) + '</button>').join("") + '</div><div class="approval-list">' + (page.items.length?page.items.map(renderPendingCard).join(""):'<div class="empty">' + t("noActions") + '</div>') + '</div>' + renderPager("actions",page.current,page.total) + '</div>';
}

function renderSkillsView() {
  const items = (state.summary.skills || {}).items || [];
  const q = (state.rulesSearch || "").trim().toLowerCase();
  const filtered = q ? items.filter(s => (s.name + " " + (s.description||"") + " " + (s.permissions||[]).join(" ")).toLowerCase().includes(q)) : items;
  return '<div class="stack-view"><div class="rules-header"><h3>' + t("skillsTitle") + ' <span class="rule-count">' + filtered.length + '</span></h3><input class="rules-search" id="skills-s" placeholder="搜索 skill…" value="' + esc(state.rulesSearch||"") + '"></div>'
    + (filtered.length ? '<div class="skills-grid">' + filtered.map(s => {
      const en = !!s.enabled;
      return '<article class="skill-card"><div class="skill-head"><div class="skill-name"><strong>' + esc(s.name) + '</strong><span class="skill-desc">' + esc(s.description||"") + '</span></div>'
        + '<button class="skill-toggle ' + (en?"on":"off") + '" data-skill="' + esc(s.name) + '" data-enabled="' + (en?"1":"0") + '">' + (en?"已启用":"已停用") + '</button></div>'
        + ((s.permissions||[]).length ? '<div class="skill-perms">' + s.permissions.slice(0, 8).map(p => '<span class="tl-tag">' + esc(p) + '</span>').join("") + '</div>' : "")
        + '</article>';
    }).join("") + '</div>' : '<div class="empty">' + t("skillsEmpty") + '</div>')
    + '</div>';
}

/* ── Rules ───────────────────────────── */
function renderRulesView() {
  const rules = _allRules(); const q = (state.rulesSearch||"").trim().toLowerCase();
  const f = q ? rules.filter(r=>(r.ruleId+r.title+r.desc+r.at.join(" ")).toLowerCase().includes(q)) : rules;
  return '<div class="stack-view"><div class="rules-header"><h3>' + t("rulesTitle") + ' <span class="rule-count">' + f.length + t("rulesTotal") + '</span></h3><input class="rules-search" id="rules-s" placeholder="' + t("rulesSearch") + '" value="' + esc(state.rulesSearch||"") + '"></div><div class="rules-grid">' + f.map(_rr).join("") + '</div></div>';
}
function _allRules() {
  const b = [
    {ruleId:"CMD-001",title:"阻断 rm -rf",desc:"递归强删默认阻断。",at:["command_exec"],sv:"critical",dc:"block",grp:"command"},
    {ruleId:"CMD-002",title:"阻断 curl 管道执行",desc:"curl|sh 供应链风险。",at:["command_exec"],sv:"critical",dc:"block",grp:"command"},
    {ruleId:"CMD-003",title:"阻断 wget 管道执行",desc:"wget|bash 供应链风险。",at:["command_exec"],sv:"critical",dc:"block",grp:"command"},
    {ruleId:"CMD-004",title:"升级 sudo",desc:"提权命令需要二次确认。",at:["command_exec"],sv:"high",dc:"escalate",grp:"command"},
    {ruleId:"CMD-005",title:"升级 ssh",desc:"远程连接命令需要二次确认。",at:["command_exec"],sv:"high",dc:"escalate",grp:"command"},
    {ruleId:"CMD-006",title:"升级 scp",desc:"远程复制命令需要二次确认。",at:["command_exec"],sv:"high",dc:"escalate",grp:"command"},
    {ruleId:"CMD-007",title:"确认 chmod",desc:"权限变更命令需要审批。",at:["command_exec"],sv:"high",dc:"ask",grp:"command"},
    {ruleId:"CMD-008",title:"确认 chown",desc:"属主变更命令需要审批。",at:["command_exec"],sv:"high",dc:"ask",grp:"command"},
    {ruleId:"CMD-009",title:"确认 mv",desc:"批量移动命令可能影响证据链。",at:["command_exec"],sv:"medium",dc:"ask",grp:"command"},
    {ruleId:"CMD-010",title:"确认 rm",desc:"普通删除命令需要审批。",at:["command_exec"],sv:"high",dc:"ask",grp:"command"},
    {ruleId:"FILE-001",title:"阻断系统目录删除",desc:"系统目录删除默认阻断。",at:["file_delete"],sv:"critical",dc:"block",grp:"file"},
    {ruleId:"FILE-002",title:"阻断敏感凭据目录删除",desc:"删除 SSH/云凭据目录会破坏凭据。",at:["file_delete"],sv:"critical",dc:"block",grp:"file"},
    {ruleId:"FILE-003",title:"确认工作区外删除",desc:"工作区外删除需要审批。",at:["file_delete"],sv:"high",dc:"ask",grp:"file"},
    {ruleId:"FILE-004",title:"确认日志删除",desc:"删除日志会影响取证。",at:["file_delete"],sv:"high",dc:"ask",grp:"file"},
    {ruleId:"FILE-005",title:"确认证据目录删除",desc:"证据目录删除需要审批。",at:["file_delete"],sv:"critical",dc:"escalate",grp:"file"},
    {ruleId:"FILE-006",title:"阻断配置覆盖",desc:"覆盖 openclaw.json 默认阻断。",at:["config_modify"],sv:"critical",dc:"block",grp:"file"},
    {ruleId:"FILE-007",title:"确认工作区外写入",desc:"写入工作区外文件需要审批。",at:["file_write"],sv:"high",dc:"ask",grp:"file"},
    {ruleId:"FILE-008",title:"确认脚本写入",desc:"写入脚本文件需要审批。",at:["file_write"],sv:"high",dc:"ask",grp:"file"},
    {ruleId:"FILE-009",title:"阻断敏感凭据写入",desc:"写入 SSH/API 凭据默认阻断。",at:["file_write"],sv:"critical",dc:"block",grp:"file"},
    {ruleId:"FILE-010",title:"确认批量写入",desc:"多目标写入需要审批。",at:["file_write"],sv:"medium",dc:"ask",grp:"file"},
    {ruleId:"NET-001",title:"确认外部 HTTP 访问",desc:"外部网络访问需要审批。",at:["network_egress"],sv:"high",dc:"ask",grp:"network"},
    {ruleId:"NET-002",title:"阻断未知公网 IP",desc:"未知公网目标默认阻断。",at:["network_egress"],sv:"critical",dc:"block",grp:"network"},
    {ruleId:"NET-003",title:"升级 webhook",desc:"Webhook 发送需要二次确认。",at:["network_egress"],sv:"high",dc:"escalate",grp:"network"},
    {ruleId:"NET-004",title:"确认上传",desc:"外传关键词触发审批。",at:["network_egress"],sv:"high",dc:"ask",grp:"network"},
    {ruleId:"NET-005",title:"阻断敏感外传",desc:"携带凭据外发默认阻断。",at:["network_egress"],sv:"critical",dc:"block",grp:"network"},
    {ruleId:"NET-006",title:"确认代理切换",desc:"修改代理出口需要审批。",at:["network_egress"],sv:"medium",dc:"ask",grp:"network"},
    {ruleId:"API-001",title:"确认危险 API",desc:"危险 API 调用需要审批。",at:["channel_send"],sv:"high",dc:"ask",grp:"api"},
    {ruleId:"API-002",title:"阻断敏感 API",desc:"敏感 API 越权默认阻断。",at:["channel_send"],sv:"critical",dc:"block",grp:"api"},
    {ruleId:"API-003",title:"确认通道发送",desc:"跨渠道发送需要审批。",at:["channel_send"],sv:"high",dc:"ask",grp:"api"},
    {ruleId:"API-004",title:"升级群发",desc:"批量发送需要二次确认。",at:["channel_send"],sv:"high",dc:"escalate",grp:"api"},
    {ruleId:"SKL-001",title:"确认 shell skill",desc:"Shell 型 skill 需要审批。",at:["skill_run"],sv:"high",dc:"ask",grp:"skill"},
    {ruleId:"SKL-002",title:"确认 network skill",desc:"具备外联能力的 skill 需要审批。",at:["skill_run"],sv:"high",dc:"ask",grp:"skill"},
    {ruleId:"SKL-003",title:"确认 delete skill",desc:"具备删除能力的 skill 需要审批。",at:["skill_run"],sv:"high",dc:"ask",grp:"skill"},
    {ruleId:"SKL-004",title:"确认 write skill",desc:"具备写入能力的 skill 需要审批。",at:["skill_run"],sv:"high",dc:"ask",grp:"skill"},
    {ruleId:"SKL-005",title:"阻断持久化 skill",desc:"自启动/守护能力默认阻断。",at:["skill_run"],sv:"critical",dc:"block",grp:"skill"},
    {ruleId:"SKL-006",title:"升级系统管理 skill",desc:"系统管理类 skill 需二次确认。",at:["skill_run"],sv:"high",dc:"escalate",grp:"skill"},
    {ruleId:"CFG-001",title:"确认配置修改",desc:"修改 OpenClaw 关键配置需要审批。",at:["config_modify"],sv:"high",dc:"ask",grp:"config"},
    {ruleId:"CFG-002",title:"阻断鉴权关闭",desc:"关闭鉴权默认阻断。",at:["config_modify"],sv:"critical",dc:"block",grp:"config"},
    {ruleId:"CFG-003",title:"确认审批绕过",desc:"绕过审批配置需要审批。",at:["config_modify"],sv:"high",dc:"ask",grp:"config"},
    {ruleId:"CFG-004",title:"确认沙箱关闭",desc:"关闭沙箱需要审批。",at:["config_modify"],sv:"high",dc:"ask",grp:"config"},
    {ruleId:"CFG-005",title:"阻断日志关闭",desc:"关闭审计日志默认阻断。",at:["config_modify"],sv:"critical",dc:"block",grp:"config"},
    {ruleId:"GEN-001",title:"确认未解析删除",desc:"删除动作未解析目标路径时先审批。",at:["file_delete"],sv:"high",dc:"ask",grp:"general"},
    {ruleId:"GEN-002",title:"确认未解析写入",desc:"写入动作未解析目标路径时先审批。",at:["file_write"],sv:"high",dc:"ask",grp:"general"},
    {ruleId:"GEN-003",title:"确认未解析命令",desc:"高危命令模糊时先审批。",at:["command_exec"],sv:"medium",dc:"ask",grp:"general"},
    {ruleId:"GEN-004",title:"确认未知外联",desc:"未知外部连接先审批。",at:["network_egress"],sv:"high",dc:"ask",grp:"general"},
    {ruleId:"GEN-005",title:"升级高价值路径",desc:"命中高价值路径需要二次确认。",at:["file_delete","file_write"],sv:"critical",dc:"escalate",grp:"general"},
    {ruleId:"GEN-006",title:"阻断批量敏感操作",desc:"一次命中多个敏感目标默认阻断。",at:["file_delete","file_write"],sv:"critical",dc:"block",grp:"general"},
  ];
  const o = [
    {ruleId:"SEM-OFFICE-001",title:"阻断敏感邮件外发",desc:"邮件外发包含敏感信息时阻断。",at:["mail_send"],sv:"critical",dc:"block",grp:"office"},
    {ruleId:"SEM-OFFICE-002",title:"阻断日报内部外发",desc:"日报外发包含内部来源内容时阻断。",at:["report_send"],sv:"critical",dc:"block",grp:"office"},
    {ruleId:"SEM-OFFICE-003",title:"升级邮件群发",desc:"邮件群发需要二次确认。",at:["mail_send"],sv:"high",dc:"escalate",grp:"office"},
    {ruleId:"SEM-OFFICE-004",title:"确认 AI 草拟邮件",desc:"AI 自动生成邮件需人工复核后发送。",at:["mail_send"],sv:"medium",dc:"ask",grp:"office"},
    {ruleId:"SEM-OFFICE-005",title:"确认日报生成范围",desc:"日报生成缺少明确时间或范围约束。",at:["report_generate"],sv:"medium",dc:"ask",grp:"office"},
  ];
  return b.concat(o);
}
function _rr(r) {
  return '<article class="rule-card"><span class="rule-id">' + esc(r.ruleId) + '</span><h4>' + esc(r.title) + '</h4><div class="rule-desc">' + esc(r.desc) + '</div><div class="rule-meta"><span class="rule-tag sev-'+r.sv+'">' + r.sv + '</span><span class="rule-tag dec-'+r.dc+'">' + r.dc + '</span>' + r.at.map(a=>'<span class="rule-tag">' + a + '</span>').join("") + (r.grp==="office"? '<span class="rule-tag office">办公策略</span>' : '') + '<span class="rule-tag">' + r.grp + '</span></div></article>';
}

/* ── Settings ─────────────────────────── */
function scanCards() {
  const b = state.summary.baseline || {};
  const c = b.checks && b.checks.length ? b.checks : b.findings ? b.findings.map((f,i)=>({check_id:f.finding_id||"f-"+i,category:f.category||"audit",title:f.title||"",status:f.severity==="critical"||f.severity==="high"?"risk":"warn",severity:f.severity||"medium",description:f.description||"",recommendation:f.recommendation||"",evidence:f.evidence||{}})) : [];
  const g = {config:{key:"config",title:t("scanCategory_config"),checks:c.filter(x=>x.category==="config")},runtime:{key:"runtime",title:t("scanCategory_runtime"),checks:c.filter(x=>["runtime","network","os"].includes(x.category))},dependency:{key:"dependency",title:t("scanCategory_dependency"),checks:c.filter(x=>x.category==="dependency")},audit:{key:"audit",title:t("scanCategory_audit"),checks:c}};
  return Object.values(g).map(g=>{const rc=g.checks.filter(x=>x.status==="risk").length,wc=g.checks.filter(x=>x.status==="warn").length,t=rc>0?"risk":wc>0?"warn":"ok";return{...g,tone:t,count:rc+wc,totalChecks:g.checks.length};});
}
function selectedScanCard(){const c=scanCards();return c.find(x=>x.key===state.scan.selected)||c[0];}
function renderSettingsView() {
  const cards=scanCards(),sel=selectedScanCard(),p=Math.max(0,Math.min(100,Number(state.scan.progress||0)));
  return '<div class="settings-grid"><article class="card scan-card'+(state.scan.running?" scan-running":"")+'"><div class="card-head"><h3>'+t("scanTitle")+'</h3></div><div class="scan-shell"><div class="scan-copy"><strong>'+(state.scan.running?t("scanRunning"):state.scan.result?t("scanFinished"):t("scanIdle"))+'</strong><p>'+t("scanHint")+'</p><div class="scan-phase-row"><span>'+t("scanProgress")+'</span><strong>'+t(state.scan.phase||"scanStage_prepare")+'</strong></div><div class="scan-stage-track"><span style="width:'+p+'%"></span></div><div class="settings-actions"><button id="run-baseline" class="btn primary"'+(state.scan.running?" disabled":"")+'>'+(state.scan.running?t("scanRunning"):t("scanStart"))+'</button><button id="export-audit" class="btn">'+t("auditExport")+'</button></div></div></div><div class="scan-grid">'+cards.map(c=>'<button class="scan-item tone-'+c.tone+(state.scan.selected===c.key?" active":"")+'" data-scan-key="'+c.key+'"><div class="scan-item-body"><div class="scan-item-head"><strong>'+esc(c.title)+'</strong><span>'+(c.tone==="risk"?t("scanStatus_risk"):c.tone==="warn"?t("scanStatus_warn"):t("scanStatus_ok"))+'</span></div><div class="scan-item-overview"><div class="scan-metric"><label>'+t("scanIssues")+'</label><strong>'+c.count+'</strong></div><div class="scan-metric"><label>'+t("scanChecks")+'</label><strong>'+c.totalChecks+'</strong></div></div></div></button>').join("")+'</div><div class="scan-detail"><div class="card-head"><h3>'+esc(sel?.title||t("scanDetails"))+'</h3><span class="status-chip">'+(sel?.tone==="risk"?t("scanStatus_risk"):sel?.tone==="warn"?t("scanStatus_warn"):t("scanStatus_ok"))+'</span></div><div class="scan-detail-list">'+((sel?.checks||[]).length?sel.checks.map(item=>'<article class="scan-detail-card tone-'+(item.status||"ok")+'"><div class="scan-detail-head"><div class="scan-detail-title"><strong>'+esc(item.title||"")+'</strong><span>'+esc(item.check_id||"")+'</span></div><span class="risk-chip">'+(item.status==="ok"?t("scanStatus_ok"):item.status==="warn"?t("scanStatus_warn"):t("scanStatus_risk"))+'</span></div><p>'+esc(item.description||"")+'</p>'+(item.evidence&&Object.keys(item.evidence).length?'<div class="scan-detail-evidence">'+esc(JSON.stringify(item.evidence))+'</div>':"")+(item.recommendation?'<div class="scan-detail-rec"><strong>修改建议</strong><div>'+esc(item.recommendation)+'</div></div>':"")+'</article>').join(""):'<div class="empty">暂无检查项</div>')+'</div></div></article></div>';
}

/* ── Shared card ──────────────────────── */
function renderPendingCard(item) {
  const d=item.decision||{},ip=item.status==="pending_approval",il=item._loading;
  return '<article class="approval-card tone-'+esc(d.risk_level||"safe")+(il?" card-loading":"")+'"><div class="approval-head"><span class="risk-chip">'+esc(d.risk_level||"safe")+'</span><span class="status-chip">'+t("status_"+(item.status||"unknown"))+'</span></div><h4>'+esc(item.target_summary||item.source_message||"")+'</h4><p>'+esc(d.reason||"")+'</p>'+(ip?'<div class="approval-actions"><button class="btn primary approve-action" data-id="'+esc(item.action_id)+'"'+(il?" disabled":"")+'>'+(il?t("approving"):t("approve"))+'</button><button class="btn danger reject-action" data-id="'+esc(item.action_id)+'"'+(il?" disabled":"")+'>'+(il?t("rejecting"):t("reject"))+'</button></div>':"")+'<details><summary>'+t("details")+'</summary><pre>'+esc(JSON.stringify(item,null,2))+'</pre></details></article>';
}

/* ── Main render ──────────────────────── */
let _prevView = "";
function render() {
  const root = document.getElementById("app");
  const viewChanged = _prevView !== state.view;
  _prevView = state.view;
  root.innerHTML = '<div class="shell"><aside class="sidebar"><div class="brand"><h1>'+t("appName")+'</h1><p>'+t("appSub")+'</p></div><nav class="nav">'+[["dashboard","▤",t("dashboard")],["actions","☰",t("actions")],["rules","◈",t("rules")],["skills","🔧",t("skills")],["settings","⚙",t("settings")]].map(v=>'<button class="nav-btn'+(state.view===v[0]?" active":"")+'" data-view="'+v[0]+'"><span class="nav-icon">'+v[1]+'</span>'+v[2]+'</button>').join("")+'</nav></aside><main class="main"><div class="topbar"><div class="rv-toggle"><span>'+t("rvMode")+'</span><button id="rv-toggle" class="rv-btn '+(state.rvMode?"on":"off")+'">'+(state.rvMode?t("rvModeOn"):t("rvModeOff"))+'</button></div><button class="topbar-btn primary" id="refresh-btn">'+t("refresh")+'</button></div><div class="content">'+(state.view==="actions"?renderActionsView():state.view==="rules"?renderRulesView():state.view==="skills"?renderSkillsView():state.view==="settings"?renderSettingsView():renderDashboard())+'</div></main><div id="toast-root"></div></div>';
  bind();
  // 滚动修复：仅当用户不在手动滚动时，新数据到达后保持当前滚动位置
  const el = document.getElementById("timeline-scroll");
  if (el && !state._userScrolling) {
    const isNearBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 60;
    if (isNearBottom) setTimeout(() => { el.scrollTop = el.scrollHeight; }, 30);
  }
}

/* ── Bind ─────────────────────────────── */
function bind() {
  document.querySelectorAll(".nav-btn").forEach(b=>{b.onclick=()=>setView(b.dataset.view);});
  document.getElementById("refresh-btn").onclick=()=>refreshAll();
  const rvb = document.getElementById("rv-toggle");
  if (rvb) rvb.onclick = () => { _setRvMode(!state.rvMode); render(); };
  const cab = document.getElementById("clear-actions");
  if (cab) cab.onclick = () => _clearActions();
  document.querySelectorAll(".approve-action").forEach(b=>{b.onclick=()=>approveAction(b.dataset.id);});
  document.querySelectorAll(".reject-action").forEach(b=>{b.onclick=()=>rejectAction(b.dataset.id);});
  document.querySelectorAll(".filter-chip").forEach(b=>{b.onclick=()=>{state.actionFilter=b.dataset.f;state.pages.actions=1;render();};});
  document.querySelectorAll(".pager-btn").forEach(b=>{b.onclick=()=>setPage(b.dataset.key,b.dataset.n==="1"?1:-1);});
  const rb=document.getElementById("run-baseline");if(rb)rb.onclick=()=>runBaseline();
  const eb=document.getElementById("export-audit");if(eb)eb.onclick=()=>exportAudit();
  document.querySelectorAll(".scan-item").forEach(b=>{b.onclick=()=>{state.scan.selected=b.dataset.scanKey;render();};});
  const ri=document.getElementById("rules-s");if(ri){ri.oninput=e=>{state.rulesSearch=e.target.value;render();};setTimeout(()=>ri.focus(),50);}
  const si=document.getElementById("skills-s");if(si){si.oninput=e=>{state.rulesSearch=e.target.value;render();};setTimeout(()=>si.focus(),50);}
  document.querySelectorAll(".skill-toggle").forEach(b=>{b.onclick=()=>toggleSkill(b.dataset.skill, b.dataset.enabled==="1");});
  // 跟踪 Trace 滚动状态：用户手动滚动时停止自动滚动
  const tl=document.getElementById("timeline-scroll");
  if(tl){
    tl.addEventListener("scroll",()=>{
      const nearBottom = tl.scrollHeight - tl.scrollTop - tl.clientHeight < 40;
      state._userScrolling = !nearBottom;
      // 3 秒无操作后恢复自动滚动
      clearTimeout(tl._scrollTimer);
      if(state._userScrolling) tl._scrollTimer = setTimeout(()=>{state._userScrolling=false;},3000);
    });
  }
}

/* ── Data ─────────────────────────────── */
async function refreshAll() {
  try { const s = await api("/api/summary"); state.summary = s; state.loading = false; state._summaryHash = _hash(s.actions); render(); }
  catch (error) { toast(error.payload?.message||t("error_default")); }
}

async function toggleSkill(name, enabled) {
  const target = !enabled;
  try {
    await api("/api/skills/upsert", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ name, enabled: target }) });
    toast(target ? "✅ 已启用 skill" : "⏸ 已停用 skill");
    await refreshAll();
  } catch (error) {
    toast(error.payload?.message || t("error_default"));
  }
}

/* ── Actions optimistic ───────────────── */
function _optimisticUpdate(id, s) {
  const a = state.summary.actions||{}, items = (a.items||[]).map(i => i.action_id===id ? {...i, status:s} : i);
  state.summary = {...state.summary, actions:{...a, items}};
}
function _setLoading(id, l) {
  const a = state.summary.actions||{}, items = (a.items||[]).map(i => i.action_id===id ? {...i, _loading:l} : i);
  state.summary = {...state.summary, actions:{...a, items}};
}
async function _clearActions() {
  if (!confirm("确定要清空所有动作历史记录吗？")) return;
  try {
    await api("/api/actions/clear", { method: "POST" });
    toast("✅ 已清空历史记录");
    await refreshAll();
  } catch (error) {
    toast(error.payload?.message || t("error_default"));
  }
}
async function approveAction(id) {
  _setLoading(id,true);render();
  try{await api("/api/actions/approve",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({action_id:id,confirmation_text:""})});_optimisticUpdate(id,"approved");toast("✅ 已批准");render();refreshAll();}
  catch(error){_setLoading(id,false);render();toast(error.payload?.message||t("error_default"));refreshAll();}
}
async function rejectAction(id) {
  _setLoading(id,true);render();
  try{await api("/api/actions/reject",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({action_id:id})});_optimisticUpdate(id,"rejected");toast("🚫 已拒绝");render();refreshAll();}
  catch(error){_setLoading(id,false);render();toast(error.payload?.message||t("error_default"));refreshAll();}
}

/* ── Scan / Audit ─────────────────────── */
async function runBaseline() {
  const phases=["scanStage_prepare","scanStage_config","scanStage_runtime","scanStage_audit"],steps=[18,42,71,92];let pi=0;
  state.scan={running:true,progress:steps[0],phase:phases[0],result:null,selected:"config"};render();
  const timer=setInterval(()=>{pi=Math.min(pi+1,phases.length-1);state.scan.phase=phases[pi];state.scan.progress=steps[pi];render();},520);
  try{const p=await api("/api/baseline/run",{method:"POST"});clearInterval(timer);state.scan={running:false,progress:100,phase:"scanStage_audit",result:p,selected:"config"};toast(t("scanFinished"));render();await refreshAll();}
  catch(error){clearInterval(timer);state.scan.running=false;toast(error.payload?.message||t("error_default"));render();}
}
async function exportAudit(){try{const p=await api("/api/audit/export",{method:"POST"});toast("✅ 导出成功："+p.json);}catch(error){toast(error.payload?.message||t("error_default"));}}
function setPage(pk,n){state.pages[pk]=Math.max(1,(state.pages[pk]||1)+n);render();}

/* ── Init ─────────────────────────────── */
render();
startPolling();
refreshAll();
