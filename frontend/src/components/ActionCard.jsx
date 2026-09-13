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
  const presentation = item.event?.metadata?.approval_presentation || {};
  const approvalDetails = presentation.details || {};
  const riskSummary = presentation.risk_summary || {};
  const trust = presentation.allow_always || {};
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

  const handleCopy = async () => {
    const command = presentation.command_preview || '';
    if (!command || typeof navigator === 'undefined' || !navigator.clipboard) {
      showToast('当前环境不支持复制');
      return;
    }
    try {
      await navigator.clipboard.writeText(command);
      showToast('已复制脱敏命令');
    } catch (_error) {
      showToast('复制失败，请手动选择文本');
    }
  };

  const rvResult = item.event?.metadata?.rv_result;

  return (
    <article class={'approval-card tone-' + esc(d.risk_level || 'safe') + (il ? ' card-loading' : '')}>
      <div class="approval-head">
        <span class="risk-chip">{esc(d.risk_level || 'safe')}</span>
        <span class="status-chip">{t('status_' + (item.status || 'unknown'))}</span>
      </div>
      <h4>{esc(presentation.intent_summary || d.user_title || (item.source === 'hook_bridge' ? 'OpenClaw 工具请求' : item.target_summary || item.source_message || ''))}</h4>
      <p class="approval-intent">{esc(userMessage)}</p>
      {(presentation.target_summary || riskSummary.level) && (
        <div class="approval-summary-grid">
          {presentation.target_summary && (
            <div><span class="approval-label">目标</span><strong>{esc(presentation.target_summary)}</strong></div>
          )}
          {riskSummary.level && (
            <div><span class="approval-label">风险</span><strong>{esc(riskSummary.level)}</strong></div>
          )}
        </div>
      )}
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
      <details class="approval-details">
        <summary>{t('details')}</summary>
        <div class="approval-detail-stack">
          {presentation.command_preview && (
            <section class="approval-section">
              <div class="approval-section-head">
                <h5>命令与参数</h5>
                <button class="btn-text" type="button" onClick={handleCopy}>复制脱敏命令</button>
              </div>
              <pre>{esc(presentation.command_preview)}</pre>
              {approvalDetails.working_directory && (
                <p class="approval-meta">工作目录：{esc(approvalDetails.working_directory)}</p>
              )}
              {approvalDetails.tool_name && (
                <p class="approval-meta">工具：{esc(approvalDetails.tool_name)}</p>
              )}
              {approvalDetails.params && Object.keys(approvalDetails.params).length > 0 && (
                <details class="params-details">
                  <summary>查看脱敏参数</summary>
                  <pre>{esc(JSON.stringify(approvalDetails.params, null, 2))}</pre>
                </details>
              )}
            </section>
          )}
          {(approvalDetails.rule_ids || item.matched_rules || []).length > 0 && (
            <section class="approval-section">
              <h5>规则与权限依据</h5>
              <div class="approval-tags">
                {(approvalDetails.rule_ids || item.matched_rules || []).slice(0, 8).map((rule) => (
                  <span class="chip chip-muted" key={rule}>{esc(rule)}</span>
                ))}
              </div>
              {riskSummary.reason && <p class="approval-meta">{esc(riskSummary.reason)}</p>}
            </section>
          )}
          {trust.eligible && trust.scope && (
            <section class="approval-section trust-section">
              <h5>精确授权范围</h5>
              <p class="approval-meta">{esc(trust.scope)} · 默认有效 {esc(trust.ttl_days || 30)} 天</p>
            </section>
          )}
          <section class="approval-section">
            <h5>运行时审计</h5>
            <pre>{esc(JSON.stringify({
              decision: d,
              resolution: item.resolution || {},
              sync_state: item.sync_state,
              execution_state: item.execution_state,
            }, null, 2))}</pre>
          </section>
        </div>
      </details>
    </article>
  );
}
