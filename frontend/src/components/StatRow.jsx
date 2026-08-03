import { useStore } from '../store';
import { esc, t } from '../i18n';

export function StatRow() {
  const summary = useStore((s) => s.summary);
  const actions = summary.actions || {};
  const counts = actions.counts || {};
  const items = actions.items || [];
  const total = counts.total || items.length;
  const b = counts.blocked || 0;
  const r = counts.rejected || 0;

  return (
    <div class="stats-row">
      <div class="stat-card">
        <div class="stat-value" style="color:#f04438">{counts.pending || 0}</div>
        <div class="stat-label">待确认</div>
      </div>
      <div class="stat-card">
        <div class="stat-value" style="color:#f79009">{b + r}</div>
        <div class="stat-label">已拦截</div>
      </div>
      <div class="stat-card">
        <div class="stat-value" style="color:#12b76a">{counts.executed || 0}</div>
        <div class="stat-label">已执行</div>
      </div>
      <div class="stat-card">
        <div class="stat-value">{total}</div>
        <div class="stat-label">总动作</div>
      </div>
    </div>
  );
}
