import { useEffect, useState } from 'preact/hooks';
import { ScanProgress } from '../components/ScanProgress';
import { apiErrorMessage, fetchApprovalTrust, revokeApprovalTrust } from '../api';
import { esc } from '../i18n';
import { useStore } from '../store';

export function Settings() {
  const [trust, setTrust] = useState([]);
  const showToast = useStore((s) => s.showToast);

  const loadTrust = async () => {
    try {
      const result = await fetchApprovalTrust();
      setTrust(Array.isArray(result.items) ? result.items : []);
    } catch (error) {
      showToast(apiErrorMessage(error, '无法读取精确授权记录'));
    }
  };

  useEffect(() => { loadTrust(); }, []);

  const handleRevoke = async (fingerprint) => {
    try {
      await revokeApprovalTrust(fingerprint);
      setTrust((items) => items.filter((item) => item.fingerprint !== fingerprint));
      showToast('已撤销精确授权');
    } catch (error) {
      showToast(apiErrorMessage(error, '撤销授权失败'));
    }
  };

  return (
    <div class="settings-grid">
      <ScanProgress />
      <article class="card trust-card">
        <div class="card-head">
          <h3>精确命令授权</h3>
          <span class="badge info">默认 30 天</span>
        </div>
        <p class="trust-intro">OpenClaw 中选择“始终允许”后，Guard 只会复用完全相同的工具、参数、工作目录和 agent/principal。</p>
        {trust.length ? (
          <div class="trust-list">
            {trust.map((item) => (
              <div class="trust-item" key={item.fingerprint}>
                <div>
                  <strong>{esc(item.scope || '精确命令')}</strong>
                  <p>有效至 {esc((item.expires_at || '').slice(0, 19).replace('T', ' '))}</p>
                </div>
                <button class="btn danger" type="button" onClick={() => handleRevoke(item.fingerprint)}>撤销</button>
              </div>
            ))}
          </div>
        ) : (
          <div class="empty">当前没有持久授权。</div>
        )}
      </article>
    </div>
  );
}
