import { useStore } from '../store';
import { esc, t } from '../i18n';
import { approveAction, rejectAction, fetchSummary } from '../api';

export function ActionCard({ item }) {
  const optimisticUpdate = useStore((s) => s.optimisticUpdate);
  const setActionLoading = useStore((s) => s.setActionLoading);
  const showToast = useStore((s) => s.showToast);
  const setSummary = useStore((s) => s.setSummary);
  const rvMode = useStore((s) => s.rvMode);

  const d = item.decision || {};
  const ip = item.status === 'pending_approval';
  const il = item._loading;

  const handleApprove = async () => {
    setActionLoading(item.action_id, true);
    try {
      await approveAction(item.action_id);
      optimisticUpdate(item.action_id, 'approved');
      showToast('✅ 已批准');
      const s = await fetchSummary();
      setSummary(s);
    } catch (error) {
      setActionLoading(item.action_id, false);
      showToast(error.payload?.message || t('error_default'));
      const s = await fetchSummary();
      setSummary(s);
    }
  };

  const handleReject = async () => {
    setActionLoading(item.action_id, true);
    try {
      await rejectAction(item.action_id);
      optimisticUpdate(item.action_id, 'rejected');
      showToast('🚫 已拒绝');
      const s = await fetchSummary();
      setSummary(s);
    } catch (error) {
      setActionLoading(item.action_id, false);
      showToast(error.payload?.message || t('error_default'));
      const s = await fetchSummary();
      setSummary(s);
    }
  };

  return (
    <article class={'approval-card tone-' + esc(d.risk_level || 'safe') + (il ? ' card-loading' : '')}>
      <div class="approval-head">
        <span class="risk-chip">{esc(d.risk_level || 'safe')}</span>
        <span class="status-chip">{t('status_' + (item.status || 'unknown'))}</span>
      </div>
      <h4>{esc(item.target_summary || item.source_message || '')}</h4>
      <p>{esc(d.reason || '')}</p>
      {rvMode && item.event?.metadata?.rv_result?.verdict && (
        <div class={'rv-badge ' + esc(item.event.metadata.rv_result.verdict)}>
          RV: {esc(item.event.metadata.rv_result.verdict.toUpperCase())}
        </div>
      )}
      {ip && (
        <div class="approval-actions">
          <button
            class="btn primary approve-action"
            data-id={esc(item.action_id)}
            disabled={il}
            onClick={handleApprove}
          >
            {il ? t('approving') : t('approve')}
          </button>
          <button
            class="btn danger reject-action"
            data-id={esc(item.action_id)}
            disabled={il}
            onClick={handleReject}
          >
            {il ? t('rejecting') : t('reject')}
          </button>
        </div>
      )}
      <details>
        <summary>{t('details')}</summary>
        <pre>{esc(JSON.stringify(item, null, 2))}</pre>
      </details>
    </article>
  );
}
