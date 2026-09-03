/**
 * i18n 国际化文本 —— 从 app.js T 对象提取。
 *
 * 保持与旧版完全相同的 key 和中文文本。
 */

const T = {
  appName: '龙虾卫士',
  appSub: 'OpenClaw 安全插件',
  dashboard: '概览',
  actions: '动作审批',
  rules: '安全规则',
  settings: '安全扫描',
  skills: '技能管理',
  connected: '已连接',
  disconnected: '未连接',
  openOpenClaw: '前往 OpenClaw 继续对话',
  approve: '确认继续',
  reject: '拒绝',
  approving: '正在确认…',
  rejecting: '正在拒绝…',
  details: '查看详情',
  status_pending_approval: '待确认',
  status_blocked: '已拦截',
  status_executed: '已执行',
  status_failed: '失败',
  status_allow: '安全放行',
  status_proposed: '待处理',
  status_rejected: '已拒绝',
  status_approved: '已批准',
  status_executing: '执行中',
  pendingTitle: '待确认动作',
  noPending: '当前没有待确认动作。',
  recentActions: '最近动作',
  noActions: '还没有动作记录。',
  scanTitle: '基线扫描',
  scanStart: '开始扫描',
  scanRunning: '正在扫描中…',
  scanFinished: '扫描完成',
  scanIdle: '准备开始基线扫描',
  scanHint: '会检查配置、端口、依赖、运行用户和审计项。',
  scanProgress: '当前阶段',
  scanStage_prepare: '准备扫描环境',
  scanStage_config: '检查配置与权限',
  scanStage_runtime: '核对运行状态与开放端口',
  scanStage_audit: '整理报告与整改建议',
  scanCategory_config: '配置与权限',
  scanCategory_runtime: '运行环境',
  scanCategory_dependency: '依赖与源代码',
  scanCategory_audit: '审计与资产',
  scanIssues: '问题',
  scanAssets: '资产',
  scanChecks: '检查项',
  scanDetails: '详细说明',
  scanStatus_ok: '正常',
  scanStatus_warn: '需留意',
  scanStatus_risk: '存在风险',
  prevPage: '上一页',
  nextPage: '下一页',
  pageInfo: '第 {current} / {total} 页',
  hookTitle: '运行时拦截状态',
  hookActive: '已接入 OpenClaw 工具拦截链',
  hookInactive: '还没有接入 OpenClaw 工具拦截链',
  hookRestart: '需要重启 OpenClaw gateway 后才会生效。',
  auditExport: '导出审计 JSON',
  clear: '清空',
  rulesTitle: '安全规则管理',
  rulesSearch: '搜索规则…',
  rulesTotal: '条规则',
  traceTitle: '安全执行链路',
  traceNoData: '暂无动作记录',
  loadingText: '正在加载…',
  error_default: '请求处理失败',
  refresh: '刷新',
  rvMode: 'RV 模式',
  rvModeOn: '开启',
  rvModeOff: '关闭',
  skillsTitle: '技能管理',
  skillsEmpty: '当前没有可管理的 skill 配置。',
};

export function t(k) {
  return T[k] || k;
}

export const SCENE_ZH = {
  mail_send: '📧 邮件发送',
  mail_read: '📬 邮件读取',
  report_send: '📋 日报外发',
  report_generate: '📝 日报生成',
  attachment_download: '📎 附件下载',
  file_delete: '🗑️ 文件删除',
  file_write: '✏️ 文件写入',
  config_modify: '⚙️ 配置修改',
  network_egress: '🌐 网络外联',
  channel_send: '📨 渠道发送',
  skill_run: '🔧 技能执行',
  command_exec: '💻 命令执行',
  chat_message: '💬 对话',
};

export function sceneZh(s) {
  return SCENE_ZH[s] || s.replace(/_/g, ' ');
}

export const STATUS_ZH = {
  pending_approval: '⏳ 待确认',
  blocked: '🚫 已拦截',
  executed: '✅ 已执行',
  executing: '🔄 执行中',
  failed: '❌ 失败',
  rejected: '🚫 已拒绝',
  approved: '✅ 已批准',
  proposed: '📋 待处理',
  allow: '✅ 已放行',
  ask: '⚠️ 需审批',
};

/** HTML 转义 */
export function esc(v) {
  return String(v ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;');
}
