import { useEffect } from 'preact/hooks';
import { useStore } from '../store';
import { t, esc } from '../i18n';
import { fetchSummary, fetchRvStatus, fetchAction, apiErrorMessage } from '../api';
import { StatRow } from '../components/StatRow';
import { ActionCard } from '../components/ActionCard';
import { HookStatus } from '../components/HookStatus';
import { TraceTimeline } from '../components/TraceTimeline';
import { RvStatusPanel } from '../components/RvStatusPanel';
import { InsightsCard } from '../components/Charts';

/* ── Polling hook ── */
function usePolling() {
  const setSummary = useStore((s) => s.setSummary);
  const setRvStatus = useStore((s) => s.setRvStatus);
  const upsertAction = useStore((s) => s.upsertAction);
  const showToast = useStore((s) => s.showToast);
  const rvMode = useStore((s) => s.rvMode);

  useEffect(() => {
    let timer;
    let source;
    let disposed = false;
    const poll = async () => {
      try {
        const s = await fetchSummary({ compact: true });
        if (!disposed) setSummary(s);
        if (rvMode) {
          const rv = await fetchRvStatus();
          if (!disposed) setRvStatus(rv);
        }
      } catch (error) {
        if (!disposed) showToast(apiErrorMessage(error, t('error_default')));
      }
    };
    poll();
    if (typeof EventSource !== 'undefined') {
      source = new EventSource('/api/events');
      const handleEvent = async (event) => {
        try {
          const payload = JSON.parse(event.data);
          if (payload.action_id) upsertAction(await fetchAction(payload.action_id));
        } catch (_) { /* 回退轮询负责最终对账 */ }
      };
      ['action.created', 'action.resolved', 'action.updated', 'action.conflict'].forEach((name) => {
        source.addEventListener(name, handleEvent);
      });
      source.onerror = () => { /* EventSource 自动重连 */ };
    }
    timer = setInterval(poll, 10000);
    return () => {
      disposed = true;
      clearInterval(timer);
      if (source) source.close();
    };
  }, [rvMode]);
}

/* ── Sub-components ── */
function HeroCard() {
  const summary = useStore((s) => s.summary);
  const chat = summary.chat || {};
  const target = summary.target || {};
  const connected = (chat.connection_state || 'disconnected') === 'connected';
  const openClawUrl = (target.web_urls && target.web_urls.length) ? target.web_urls[0] : 'http://localhost:8000';

  return (
    <section class={'card hero-card' + (connected ? ' connected' : '')}>
      <div class="hero-main">
        <div class="hero-status">
          <span class={'status-dot ' + (connected ? 'green' : 'red')}></span>
          <strong>{t(connected ? 'connected' : 'disconnected')}</strong>
        </div>
        <div class="hero-action">
          <p>{t('openOpenClaw')}</p>
          <a href={openClawUrl} target="_blank" class="btn primary hero-btn" rel="noreferrer">立即前往</a>
        </div>
      </div>
      {connected && (
        <div class="hero-meta">
          <span>模型：{esc(chat.current_model || '—')}</span>
          <span>Agent：{esc(chat.current_agent || '—')}</span>
        </div>
      )}
    </section>
  );
}

function PendingSection() {
  const summary = useStore((s) => s.summary);
  const items = (summary.actions || {}).items || [];
  const pending = items.filter((i) => i.status === 'pending_approval');

  return (
    <section class="card">
      <div class="card-head">
        <h3>{t('pendingTitle')} ({pending.length})</h3>
      </div>
      <div class="approval-list">
        {pending.length > 0
          ? pending.map((item) => <ActionCard key={item.action_id} item={item} />)
          : <div class="empty">{t('noPending')}</div>}
      </div>
    </section>
  );
}

function RecentSection() {
  const summary = useStore((s) => s.summary);
  const setSummary = useStore((s) => s.setSummary);
  const showToast = useStore((s) => s.showToast);
  const items = (summary.actions || {}).items || [];
  const recent = items.filter((item) => item.status !== 'pending_approval').slice(0, 6);

  const handleClear = async () => {
    if (!confirm('确定要清空所有动作历史记录吗？')) return;
    try {
      await fetch('/api/actions/clear', { method: 'POST' });
      showToast('✅ 已清空历史记录');
      const s = await fetchSummary();
      setSummary(s);
    } catch (error) {
      showToast(apiErrorMessage(error, t('error_default')));
    }
  };

  return (
    <section class="card">
      <div class="card-head">
        <h3>{t('recentActions')}</h3>
        {items.length > 0 && (
          <button class="btn-text danger" id="clear-actions" onClick={handleClear}>
            {t('clear')}
          </button>
        )}
      </div>
      <div class="approval-list">
        {recent.length > 0
          ? recent.map((item) => <ActionCard key={item.action_id} item={item} />)
          : <div class="empty">{t('noActions')}</div>}
      </div>
    </section>
  );
}

/* ── Main export ── */
export function Dashboard() {
  const loading = useStore((s) => s.loading);
  const summary = useStore((s) => s.summary);
  const rvMode = useStore((s) => s.rvMode);
  const items = (summary.actions || {}).items || [];

  usePolling();

  if (loading && !items.length) {
    return (
      <div class="loading-wrap">
        <div class="loading-spinner"></div>
        <p>{t('loadingText')}</p>
      </div>
    );
  }

  return (
    <div class="dashboard">
      <HeroCard />
      <StatRow />
      <InsightsCard />
      {rvMode && <TraceTimeline />}
      {rvMode && <RvStatusPanel />}
      <PendingSection />
      <RecentSection />
      <HookStatus />
    </div>
  );
}
