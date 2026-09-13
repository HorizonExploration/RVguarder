import { useStore } from '../store';
import { t, esc, sceneZh, STATUS_ZH } from '../i18n';

function stepTone(props) {
  const p = (props || []).join(' ');
  if (p.includes('block') || p.includes('secret')) return 'danger';
  if (p.includes('ask') || p.includes('escalate')) return 'warn';
  return '';
}

function stepIcon(isRunning, isPending, isBad, isWarning) {
  if (isRunning) return '🔄';
  if (isPending) return '⏳';
  if (isBad) return '🚫';
  if (isWarning) return '⚠️';
  return '✅';
}

export function TraceTimeline() {
  const summary = useStore((s) => s.summary);
  const items = (summary.actions || {}).items || [];
  const trace = items.slice(0, 10);

  return (
    <section class="card trace-card">
      <div class="card-head">
        <h3>
          <span class="trace-dot"></span> {t('traceTitle')}
        </h3>
        <span class="badge info">实时</span>
      </div>
      {!trace.length ? (
        <div class="timeline-empty">{t('traceNoData')}</div>
      ) : (
        <div class="timeline-scroll" id="timeline-scroll">
          <div class="timeline">
            {trace.map((item) => {
              const st = item.status || 'pending_approval';
              const dec = item.decision || {};
              const em = (item.event || {}).metadata || {};
              const sem = em.semantic || {};
              const approval = em.approval_presentation || {};
              const rv = em.rv_result || {};
              const timings = em.pipeline_timings_ms || {};
              const sc = sem.scenario || item.event?.action_type || 'unknown';
              const labels = sem.labels || [];
              const rsn = approval.intent_summary || dec.reason || item.target_summary || '';
              const hasApprovalDetails = Boolean(approval.target_summary || approval.command_preview || approval.risk_summary?.reason);

              const isRunning = st === 'executing';
              const isBad = st === 'blocked' || st === 'rejected' || st === 'failed' || st === 'denied';
              const isWarning = false;
              const isPending = st === 'pending_approval';
              const isDone = !isRunning && !isPending && !isBad && !isWarning;

              let cls = 'tl-step-wrap';
              if (isRunning) cls += ' running';
              else if (isPending) cls += ' pending';
              else if (isBad) cls += ' blocked';
              else if (isWarning) cls += ' warn';
              else cls += ' done';

              const icon = stepIcon(isRunning, isPending, isBad, isWarning);
              const sta = STATUS_ZH[st] || st;

              return (
                <div class={cls} key={item.action_id || item.event_id}>
                  <div class="tl-step">
                    <div class="tl-head">
                      <span class="tl-icon">{icon}</span>
                      <span class="tl-scene">{esc(sceneZh(sc))}</span>
                      <span class={'tl-status ' + st}>{sta}</span>
                    </div>
                    <div class="tl-time">
                      {esc((item.created_at || '').slice(0, 19).replace('T', ' '))}
                    </div>
                    {rsn && <div class="tl-reason">{esc(rsn)}</div>}
                    {Object.keys(timings).length > 0 && (
                      <div class="tl-chips">
                        {timings.semantic_ms !== undefined && (
                          <span class="tl-chip">语义 {esc(timings.semantic_ms)}ms</span>
                        )}
                        {timings.policy_ms !== undefined && (
                          <span class="tl-chip">PMKB {esc(timings.policy_ms)}ms</span>
                        )}
                        {timings.rv_ms !== undefined && (
                          <span class="tl-chip">RV {esc(timings.rv_ms)}ms</span>
                        )}
                        {timings.controller_ms !== undefined && (
                          <span class="tl-chip">决策 {esc(timings.controller_ms)}ms</span>
                        )}
                        {timings.total_ms !== undefined && (
                          <span class="tl-chip">总耗时 {esc(timings.total_ms)}ms</span>
                        )}
                      </div>
                    )}
                    {rv.verdict && (
                      <div class="tl-rv">
                        <div class="tl-rv-head">
                          <span class={'badge ' + (rv.verdict === 'ok' ? 'ok' : rv.verdict === 'ask' || rv.verdict === 'escalate' ? 'warn' : 'danger')}>
                            运行时验证 (RV): {esc(rv.verdict.toUpperCase())}
                          </span>
                          {rv.window_size !== undefined && (
                            <span class="tl-rv-win">窗口: {esc(rv.window_size)}</span>
                          )}
                        </div>
                        <div class="tl-rv-body">
                          {rv.triggered_by && (
                            <div><strong>触发监视器:</strong> {esc(rv.triggered_by)}</div>
                          )}
                          {rv.reason && (
                            <div><strong>判定依据:</strong> {esc(rv.reason)}</div>
                          )}
                        </div>
                      </div>
                    )}
                    {labels.length > 0 && (
                      <div class="tl-tags">
                        {labels.slice(0, 5).map((l) => (
                          <span class="tl-tag" key={l}>{esc(l)}</span>
                        ))}
                      </div>
                    )}
                    <details>
                      <summary>{t('details')}</summary>
                      <div class="timeline-detail-summary">
                        {hasApprovalDetails ? (
                          <>
                            {approval.target_summary && <div><strong>目标：</strong>{esc(approval.target_summary)}</div>}
                            {approval.command_preview && <pre>{esc(approval.command_preview)}</pre>}
                            {approval.risk_summary?.reason && <div><strong>风险依据：</strong>{esc(approval.risk_summary.reason)}</div>}
                          </>
                        ) : (
                          <div class="approval-meta">历史记录未保存当前版本的审批详情，仅显示状态与安全摘要。</div>
                        )}
                      </div>
                    </details>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </section>
  );
}
