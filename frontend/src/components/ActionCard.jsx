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

  const handleAdopt = async () => {
    setActionLoading(item.action_id, true);
    try {
      await rejectAction(item.action_id);
      optimisticUpdate(item.action_id, 'rejected');
      if (revisionHint && typeof navigator !== 'undefined' && navigator.clipboard) {
        try { await navigator.clipboard.writeText(revisionHint); } catch (_) { /* 剪贴板不可用则忽略 */ }
      }
      showToast('✅ 已采用修正建议，建议已复制到剪贴板');
      const s = await fetchSummary();
      setSummary(s);
    } catch (error) {
      setActionLoading(item.action_id, false);
      showToast(error.payload?.message || t('error_default'));
      const s = await fetchSummary();
      setSummary(s);
    }
  };

  const revisionHint = d.revision_hint;
  const sessionState = item.event?.metadata?.session_state;
  const constraint = item.event?.metadata?.constraint_result;
  const rvResult = item.event?.metadata?.rv_result;

  return (
    <article class={'approval-card tone-' + esc(d.risk_level || 'safe') + (il ? ' card-loading' : '')}>
      <div class="approval-head">
        <span class="risk-chip">{esc(d.risk_level || 'safe')}</span>
        <span class="status-chip">{t('status_' + (item.status || 'unknown'))}</span>
        {d.action === 'revise' && <span class="status-chip revise">{t('revisionHint')}</span>}
      </div>
      <h4>{esc(item.target_summary || item.source_message || '')}</h4>
      <p>{esc(d.reason || '')}</p>
      {revisionHint && (
        <div class="revision-hint">
          <strong>{t('revisionHint')}：</strong>{esc(revisionHint)}
        </div>
      )}
      {rvMode && rvResult?.verdict && (
        <div class={'rv-badge ' + esc(rvResult.verdict)}>
          RV: {esc(rvResult.verdict.toUpperCase())}
        </div>
      )}
      {constraint && (
        <div class="constraint-badge">
          约束引擎: {esc(constraint.title)} · score {esc(constraint.score)}{constraint.matched ? '' : '（未覆盖）'}
        </div>
      )}
      {sessionState && (
        <div class="session-state">
          {t('sessionState')}：{esc(sessionState.state || 'safe')}（{t('score')} {esc(sessionState.total_score ?? 0)}）
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
          {revisionHint && (
            <button
              class="btn adopt-action"
              data-id={esc(item.action_id)}
              disabled={il}
              onClick={handleAdopt}
            >
              {il ? t('rejecting') : t('adoptSuggestion')}
            </button>
          )}
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
