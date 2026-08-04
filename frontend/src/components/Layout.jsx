import { Link } from 'preact-router';
import { useStore } from '../store';
import { t } from '../i18n';
import { rvToggle } from '../api';
import { Toast } from './Toast';

/** 根据当前路径判断 nav 按钮是否 active */
function useIsActive(view) {
  if (typeof window === 'undefined') return false;
  const p = window.location.pathname;
  if (view === 'dashboard') return p === '/' || p === '';
  return p === '/' + view;
}

export function Layout({ children }) {
  const rvMode = useStore((s) => s.rvMode);
  const setRvMode = useStore((s) => s.setRvMode);
  const showToast = useStore((s) => s.showToast);
  const setSummary = useStore((s) => s.setSummary);

  const handleRvToggle = async () => {
    const on = !rvMode;
    setRvMode(on);
    showToast(on ? '🔄 RV 模式已开启 — 安全执行链路实时追踪' : '🔄 RV 模式已关闭 — 恢复标准视图');
    await rvToggle(on);
  };

  const handleRefresh = async () => {
    try {
      const s = await fetch('/api/summary').then((r) => r.json());
      setSummary(s);
    } catch (error) {
      showToast(error.payload?.message || t('error_default'));
    }
  };

  const navItems = [
    ['dashboard', '▤', t('dashboard')],
    ['actions', '☰', t('actions')],
    ['rules', '◈', t('rules')],
    ['skills', '🔧', t('skills')],
    ['settings', '⚙', t('settings')],
  ];

  return (
    <div class="shell">
      <aside class="sidebar">
        <div class="brand">
          <h1>{t('appName')}</h1>
          <p>{t('appSub')}</p>
        </div>
        <nav class="nav">
          {navItems.map(([view, icon, label]) => (
            <Link key={view} class={'nav-btn' + (useIsActive(view) ? ' active' : '')} href={view === 'dashboard' ? '/' : '/' + view}>
              <span class="nav-icon">{icon}</span>
              {label}
            </Link>
          ))}
        </nav>
      </aside>
      <main class="main">
        <div class="topbar">
          <div class="rv-toggle">
            <span>{t('rvMode')}</span>
            <button id="rv-toggle" class={'rv-btn ' + (rvMode ? 'on' : 'off')} onClick={handleRvToggle}>
              {rvMode ? t('rvModeOn') : t('rvModeOff')}
            </button>
          </div>
          <button class="topbar-btn primary" id="refresh-btn" onClick={handleRefresh}>
            {t('refresh')}
          </button>
        </div>
        <div class="content">{children}</div>
      </main>
      <Toast />
    </div>
  );
}
