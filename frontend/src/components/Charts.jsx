import { useStore } from '../store';
import { esc } from '../i18n';

/**
 * 轻量 SVG 图表（零依赖，守住首屏体积）。
 * 不引入 chart 库，用原生 SVG 自绘环形图与趋势柱状图。
 */

const ACTION_COLORS = {
  block: '#f04438',
  escalate: '#7c3aed',
  revise: '#7c3aed',
  ask: '#f79009',
  allow: '#12b76a',
};

const ACTION_LABELS = {
  block: '拦截',
  escalate: '升级',
  revise: '修订',
  ask: '询问',
  allow: '放行',
};

/** 决策分布环形图。data: [{ label, value, color }] */
export function Donut({ data, size = 116, thickness = 12 }) {
  const total = data.reduce((s, d) => s + d.value, 0);
  const r = (size - thickness) / 2;
  const c = 2 * Math.PI * r;
  const center = size / 2;
  let acc = 0;

  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} class="donut">
      <circle
        cx={center}
        cy={center}
        r={r}
        fill="none"
        stroke="var(--c-surface-4)"
        strokeWidth={thickness}
      />
      {data
        .filter((d) => d.value > 0)
        .map((d, i) => {
          const len = (d.value / total) * c;
          const seg = (
            <circle
              key={i}
              cx={center}
              cy={center}
              r={r}
              fill="none"
              stroke={d.color}
              strokeWidth={thickness}
              strokeDasharray={`${len} ${c - len}`}
              strokeDashoffset={-acc}
              transform={`rotate(-90 ${center} ${center})`}
            />
          );
          acc += len;
          return seg;
        })}
      <text x={center} y={center + 5} textAnchor="middle" class="donut-center">
        {total}
      </text>
    </svg>
  );
}

/** 近期风险趋势柱状图（旧→新）。items 为 actions items。 */
export function RiskBars({ items, max = 24 }) {
  const recent = items.slice(0, max).reverse();
  const lvl = { allow: 1, ask: 2, escalate: 3, block: 4, revise: 3 };
  const w = 8;
  const gap = 3;
  const h = 64;
  const barW = Math.max(recent.length * (w + gap), 100);

  return (
    <svg
      width="100%"
      height={h}
      viewBox={`0 0 ${barW} ${h}`}
      preserveAspectRatio="none"
      class="sparkbars"
    >
      {recent.map((it, i) => {
        const action = (it.decision || {}).action || 'allow';
        const v = lvl[action] || 1;
        const bh = Math.max(4, (v / 4) * (h - 8));
        const x = i * (w + gap);
        return (
          <rect
            key={i}
            x={x}
            y={h - bh}
            width={w}
            height={bh}
            rx={2}
            fill={ACTION_COLORS[action] || '#98a2b3'}
          />
        );
      })}
    </svg>
  );
}

/** 安全决策分布 + 风险趋势聚合卡片。 */
export function InsightsCard() {
  const summary = useStore((s) => s.summary);
  const items = (summary.actions || {}).items || [];

  const dist = { block: 0, escalate: 0, ask: 0, revise: 0, allow: 0 };
  items.forEach((it) => {
    const a = (it.decision || {}).action || 'allow';
    if (dist[a] !== undefined) dist[a] += 1;
  });

  const donutData = Object.entries(dist).map(([k, v]) => ({
    label: ACTION_LABELS[k] || k,
    value: v,
    color: ACTION_COLORS[k] || '#98a2b3',
  }));

  return (
    <section class="card insight-card">
      <div class="card-head">
        <h3>安全决策分布</h3>
      </div>
      <div class="insight-body">
        <Donut data={donutData} />
        <div class="legend">
          {donutData.map((d) => (
            <div class="legend-row" key={d.label}>
              <span class="legend-dot" style={'background:' + d.color}></span>
              <span class="legend-label">{esc(d.label)}</span>
              <strong>{d.value}</strong>
            </div>
          ))}
        </div>
      </div>
      {items.length > 0 && (
        <div class="trend-block">
          <div class="trend-head">近期风险趋势</div>
          <RiskBars items={items} />
        </div>
      )}
    </section>
  );
}
