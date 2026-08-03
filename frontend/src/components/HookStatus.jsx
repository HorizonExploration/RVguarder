import { useStore } from '../store';
import { t, esc } from '../i18n';

export function HookStatus() {
  const summary = useStore((s) => s.summary);
  const hook = summary.hook || {};
  const st = hook.state || 'unknown';

  let badge;
  if (hook.active && st === 'active') {
    badge = <span class="badge ok">{t('hookActive')}</span>;
  } else if (st === 'loaded_waiting_restart') {
    badge = <span class="badge warn">⏳ 已配置，需重启 Gateway</span>;
  } else if (st === 'runtime_unreachable') {
    badge = <span class="badge warn">⚠️ OpenClaw Gateway 未连接</span>;
  } else if (st === 'plugin_invalid') {
    badge = <span class="badge danger">❌ 插件文件异常</span>;
  } else {
    badge = <span class="badge warn">{t('hookInactive')}</span>;
  }

  return (
    <section class="card">
      <div class="card-head">
        <h3>{t('hookTitle')}</h3>
      </div>
      <div class="hook-status">
        {badge}
        {hook.error_detail && <p class="hook-detail">{esc(hook.error_detail)}</p>}
        {hook.runtime_hint && <p class="hook-hint">{esc(hook.runtime_hint)}</p>}
      </div>
    </section>
  );
}
