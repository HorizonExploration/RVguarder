import { esc } from '../i18n';

export function RuleCard({ rule }) {
  return (
    <article class="rule-card">
      <span class="rule-id">{esc(rule.ruleId)}</span>
      <h4>{esc(rule.title)}</h4>
      <div class="rule-desc">{esc(rule.desc)}</div>
      <div class="rule-meta">
        <span class={'rule-tag sev-' + rule.sv}>{rule.sv}</span>
        <span class={'rule-tag dec-' + rule.dc}>{rule.dc}</span>
        {rule.at.map((a) => (
          <span class="rule-tag" key={a}>{a}</span>
        ))}
        {rule.grp === 'office' && <span class="rule-tag office">办公策略</span>}
        <span class="rule-tag">{rule.grp}</span>
      </div>
    </article>
  );
}
