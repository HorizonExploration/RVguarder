import { useStore } from '../store';
import { t, esc } from '../i18n';
import { SkillCard } from '../components/SkillCard';

export function Skills() {
  const summary = useStore((s) => s.summary);
  const rulesSearch = useStore((s) => s.rulesSearch);
  const setRulesSearch = useStore((s) => s.setRulesSearch);

  const items = (summary.skills || {}).items || [];
  const q = (rulesSearch || '').trim().toLowerCase();
  const filtered = q
    ? items.filter((s) =>
        (s.name + ' ' + (s.description || '') + ' ' + (s.permissions || []).join(' '))
          .toLowerCase()
          .includes(q)
      )
    : items;

  return (
    <div class="stack-view">
      <div class="rules-header">
        <h3>
          {t('skillsTitle')} <span class="rule-count">{filtered.length}</span>
        </h3>
        <input
          class="rules-search"
          id="skills-s"
          placeholder="搜索 skill…"
          value={rulesSearch || ''}
          onInput={(e) => setRulesSearch(e.target.value)}
        />
      </div>
      {filtered.length > 0 ? (
        <div class="skills-grid">
          {filtered.map((s) => (
            <SkillCard key={s.name} skill={s} />
          ))}
        </div>
      ) : (
        <div class="empty">{t('skillsEmpty')}</div>
      )}
    </div>
  );
}
