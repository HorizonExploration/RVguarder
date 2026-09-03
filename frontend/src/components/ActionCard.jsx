import { useStore } from '../store';
import { esc, t } from '../i18n';
import { approveAction, rejectAction, fetchSummary, apiErrorMessage } from '../api';

export function ActionCard({ item }) {
  const optimisticUpdate = useStore((s) => s.optimisticUpdate);
  const setActionLoading = useStore((s) => s.setActionLoading);
  const showToast = useStore((s) => s.showToast);
  const setSummary = useStore((s) => s.setSummary);
  const rvMode = useStore((s) => s.rvMode);

  const d = item.decision || {};
  const userMessage = d.user_message || item.user_message || d.reason || '';
  const ip = item.status === 'pending_approval';
  const canApprove = item.source !== 'hook_bridge' && !item.event?.metadata?.hook_bridge;
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
      showToast(apiErrorMessage(error, t('error_default')));
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
      showToast(apiErrorMessage(error, t('error_default')));
      const s = await fetchSummary();
      setSummary(s);
    }
  };

  const rvResult = item.event?.metadata?.rv_result;

  return (
    <article class={'approval-card tone-' + esc(d.risk_level || 'safe') + (il ? ' card-loading' : '')}>
      <div class="approval-head">
        <span class="risk-chip">{esc(d.risk_level || 'safe')}</span>
        <span class="status-chip">{t('status_' + (item.status || 'unknown'))}</span>
      </div>
      <h4>{esc(d.user_title || item.target_summary || item.source_message || '')}</h4>
      <p>{esc(userMessage)}</p>
      {item.source === 'hook_bridge' && (
        <div class="sync-hint">请在 OpenClaw 审批中心处理 · 同步状态：{esc(item.sync_state || 'local_only')}</div>
      )}
      {rvMode && rvResult?.verdict && (
        <div class={'rv-badge ' + esc(rvResult.verdict)}>
          RV: {esc(rvResult.verdict.toUpperCase())}
        </div>
      )}
      {ip && canApprove && (
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
