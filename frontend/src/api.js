/**
 * API 请求层 —— fetch wrapper + 全部后端端点。
 *
 * 从 app.js 提取，保持与旧版完全相同的调用签名和行为。
 */

/** 通用 fetch wrapper —— 非 2xx → throw */
export async function api(path, opts = {}) {
  const r = await fetch(path, opts);
  const pl = await r.json().catch(() => ({}));
  if (!r.ok) {
    const e = new Error(pl.error_code || pl.error || 'request_failed');
    e.payload = pl;
    throw e;
  }
  return pl;
}

export function apiErrorMessage(error, fallback = '请求处理失败') {
  return error?.payload?.detail || error?.payload?.message || error?.payload?.error || error?.message || fallback;
}

/** GET /api/summary */
export async function fetchSummary({ compact = false } = {}) {
  return api(compact ? '/api/summary?view=compact' : '/api/summary');
}

/** GET /api/rv/status */
export async function fetchRvStatus() {
  return api('/api/rv/status');
}

/** GET /api/actions/{action_id} */
export async function fetchAction(id) {
  const result = await api(`/api/actions/${encodeURIComponent(id)}`);
  return result.action;
}

/** POST /api/actions/approve */
export async function approveAction(id) {
  return api('/api/actions/approve', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action_id: id, confirmation_text: '' }),
  });
}

/** POST /api/actions/reject */
export async function rejectAction(id) {
  return api('/api/actions/reject', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action_id: id }),
  });
}

/** POST /api/actions/clear */
export async function clearActions() {
  return api('/api/actions/clear', { method: 'POST' });
}

/** POST /api/rv/toggle */
export async function rvToggle(enabled) {
  return api('/api/rv/toggle', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ enabled }),
  });
}

/** POST /api/baseline/run */
export async function runBaseline() {
  return api('/api/baseline/run', { method: 'POST' });
}

/** POST /api/audit/export */
export async function exportAudit() {
  return api('/api/audit/export', { method: 'POST' });
}

/** POST /api/skills/upsert */
export async function upsertSkill(name, enabled) {
  return api('/api/skills/upsert', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name, enabled }),
  });
}
