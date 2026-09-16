import { useStore } from '../store';
import { t, esc } from '../i18n';
import { fetchSummary, runBaseline, exportAudit, apiErrorMessage } from '../api';

const PHASES = ['scanStage_prepare', 'scanStage_config', 'scanStage_runtime', 'scanStage_audit'];
const STEPS = [18, 42, 71, 92];

export function ScanProgress() {
  const scan = useStore((s) => s.scan);
  const setScan = useStore((s) => s.setScan);
  const showToast = useStore((s) => s.showToast);
  const setSummary = useStore((s) => s.setSummary);
  const summary = useStore((s) => s.summary);

  const pct = Math.max(0, Math.min(100, Number(scan.progress || 0)));

  const handleRunBaseline = async () => {
    let pi = 0;
    setScan({ running: true, progress: STEPS[0], phase: PHASES[0], result: null });
    const timer = setInterval(() => {
      pi = Math.min(pi + 1, PHASES.length - 1);
      setScan({ phase: PHASES[pi], progress: STEPS[pi] });
    }, 520);
    try {
      const p = await runBaseline();
      clearInterval(timer);
      setScan({ running: false, progress: 100, phase: 'scanStage_audit', result: p });
      showToast(t('scanFinished'));
    } catch (error) {
      clearInterval(timer);
      setScan({ running: false });
      showToast(apiErrorMessage(error, t('error_default')));
    }
    const s = await fetchSummary().catch(() => ({}));
    setSummary(s);
  };

  const handleExportAudit = async () => {
    try {
      const p = await exportAudit();
      showToast('✅ 导出成功：' + p.json);
    } catch (error) {
      showToast(apiErrorMessage(error, t('error_default')));
    }
  };

  // Build scan cards from baseline data
  const b = summary.baseline || {};
  const c =
    b.checks && b.checks.length
      ? b.checks
      : b.findings
      ? b.findings.map((f, i) => ({
          check_id: f.finding_id || 'f-' + i,
          category: f.category || 'audit',
          title: f.title || '',
          status: f.severity === 'critical' || f.severity === 'high' ? 'risk' : 'warn',
          severity: f.severity || 'medium',
          description: f.description || '',
          recommendation: f.recommendation || '',
          evidence: f.evidence || {},
        }))
      : [];

  const groups = [
    { key: 'config', title: t('scanCategory_config'), checks: c.filter((x) => x.category === 'config') },
    { key: 'runtime', title: t('scanCategory_runtime'), checks: c.filter((x) => ['runtime', 'network', 'os'].includes(x.category)) },
    { key: 'dependency', title: t('scanCategory_dependency'), checks: c.filter((x) => x.category === 'dependency') },
    { key: 'audit', title: t('scanCategory_audit'), checks: c },
  ].map((g) => {
    const rc = g.checks.filter((x) => x.status === 'risk').length;
    const wc = g.checks.filter((x) => x.status === 'warn').length;
    const tone = rc > 0 ? 'risk' : wc > 0 ? 'warn' : 'ok';
    return { ...g, tone, count: rc + wc, totalChecks: g.checks.length };
  });

  const sel = groups.find((x) => x.key === scan.selected) || groups[0];

  return (
    <div class="settings-grid">
      <article class={'card scan-card' + (scan.running ? ' scan-running' : '')}>
        <div class="card-head">
          <h3>{t('scanTitle')}</h3>
        </div>
        <div class="scan-shell">
          <div class="scan-copy">
            <strong>
              {scan.running ? t('scanRunning') : scan.result ? t('scanFinished') : t('scanIdle')}
            </strong>
            <p>{t('scanHint')}</p>
            <div class="scan-phase-row">
              <span>{t('scanProgress')}</span>
              <strong>{t(scan.phase || 'scanStage_prepare')}</strong>
            </div>
            <div class="scan-stage-track">
              <span style={'width:' + pct + '%'}></span>
            </div>
            <div class="settings-actions">
              <button id="run-baseline" class="btn primary" disabled={scan.running} onClick={handleRunBaseline}>
                {scan.running ? t('scanRunning') : t('scanStart')}
              </button>
              <button id="export-audit" class="btn" onClick={handleExportAudit}>
                {t('auditExport')}
              </button>
            </div>
          </div>
        </div>
        <div class="scan-grid">
          {groups.map((g) => (
            <button
              key={g.key}
              class={'scan-item tone-' + g.tone + (scan.selected === g.key ? ' active' : '')}
              data-scan-key={g.key}
              onClick={() => setScan({ selected: g.key })}
            >
              <div class="scan-item-body">
                <div class="scan-item-head">
                  <strong>{esc(g.title)}</strong>
                  <span>
                    {g.tone === 'risk' ? t('scanStatus_risk') : g.tone === 'warn' ? t('scanStatus_warn') : t('scanStatus_ok')}
                  </span>
                </div>
                <div class="scan-item-overview">
                  <div class="scan-metric">
                    <label>{t('scanIssues')}</label>
                    <strong>{g.count}</strong>
                  </div>
                  <div class="scan-metric">
                    <label>{t('scanChecks')}</label>
                    <strong>{g.totalChecks}</strong>
                  </div>
                </div>
              </div>
            </button>
          ))}
        </div>
        <div class="scan-detail">
          <div class="card-head">
            <h3>{esc(sel?.title || t('scanDetails'))}</h3>
            <span class="status-chip">
              {sel?.tone === 'risk' ? t('scanStatus_risk') : sel?.tone === 'warn' ? t('scanStatus_warn') : t('scanStatus_ok')}
            </span>
          </div>
          <div class="scan-detail-list">
            {(sel?.checks || []).length > 0 ? (
              sel.checks.map((item, i) => (
                <article key={item.check_id || i} class={'scan-detail-card tone-' + (item.status || 'ok')}>
                  <div class="scan-detail-head">
                    <div class="scan-detail-title">
                      <strong>{esc(item.title || '')}</strong>
                      <span>{esc(item.check_id || '')}</span>
                    </div>
                    <span class="risk-chip">
                      {item.status === 'ok' ? t('scanStatus_ok') : item.status === 'warn' ? t('scanStatus_warn') : t('scanStatus_risk')}
                    </span>
                  </div>
                  <p>{esc(item.description || '')}</p>
                  {item.evidence && Object.keys(item.evidence).length > 0 && (
                    <div class="scan-detail-evidence">{esc(JSON.stringify(item.evidence))}</div>
                  )}
                  {item.recommendation && (
                    <div class="scan-detail-rec">
                      <strong>修改建议</strong>
                      <div>{esc(item.recommendation)}</div>
                    </div>
                  )}
                </article>
              ))
            ) : (
              <div class="empty">暂无检查项</div>
            )}
          </div>
        </div>
      </article>
    </div>
  );
}
