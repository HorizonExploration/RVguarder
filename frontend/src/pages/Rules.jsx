import { useStore } from '../store';
import { t } from '../i18n';
import { RuleCard } from '../components/RuleCard';
import { BUILTIN_RULES } from '../rules-data';

export function Rules() {
  const rulesSearch = useStore((s) => s.rulesSearch);
  const setRulesSearch = useStore((s) => s.setRulesSearch);

  const q = (rulesSearch || '').trim().toLowerCase();
  const filtered = q
    ? BUILTIN_RULES.filter((r) =>
        (r.ruleId + r.title + r.desc + r.at.join(' ')).toLowerCase().includes(q)
      )
    : BUILTIN_RULES;

  return (
    <div class="stack-view">
      <div class="rules-header">
        <h3>
          {t('rulesTitle')} <span class="rule-count">{filtered.length}{t('rulesTotal')}</span>
        </h3>
        <input
          class="rules-search"
          id="rules-s"
          placeholder={t('rulesSearch')}
          value={rulesSearch || ''}
          onInput={(e) => setRulesSearch(e.target.value)}
        />
      </div>
      <div class="rules-grid">
        {filtered.map((r) => (
          <RuleCard key={r.ruleId} rule={r} />
        ))}
      </div>
    </div>
  );
}
