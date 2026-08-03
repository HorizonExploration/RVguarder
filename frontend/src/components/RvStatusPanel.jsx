import { useStore } from '../store';
import { esc } from '../i18n';

function stepTone(props) {
  const p = (props || []).join(' ');
  if (p.includes('block') || p.includes('secret')) return 'danger';
  if (p.includes('ask') || p.includes('escalate')) return 'warn';
  return '';
}

export function RvStatusPanel() {
  const rvStatus = useStore((s) => s.rvStatus);
  if (!rvStatus || !rvStatus.engine) return null;

  const eng = rvStatus.engine;
  const win = eng.window_snapshot || [];

  return (
    <section class="card rv-status-card">
      <div class="card-head">
        <h3>🔄 运行时验证引擎</h3>
        <span class="badge info">活跃</span>
      </div>
      <div class="rv-status-grid">
        <div class="rv-stat">
          <span class="rv-stat-label">监视器</span>
          <strong>{esc(eng.monitor_count || 0)}</strong>
        </div>
        <div class="rv-stat">
          <span class="rv-stat-label">窗口大小</span>
          <strong>{esc(eng.window_size || 0)}</strong>
        </div>
      </div>
      {win.length > 0 && (
        <div class="rv-window">
          <div class="rv-window-head">滑动窗口快照</div>
          <div class="rv-window-steps">
            {win.slice(-5).map((s, i) => (
              <span key={i} class={'rv-window-step' + (stepTone(s.props) ? ' tone-' + stepTone(s.props) : '')}>
                {esc(s.event || '?')}
              </span>
            ))}
          </div>
        </div>
      )}
    </section>
  );
}
