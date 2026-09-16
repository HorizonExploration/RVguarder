import { create } from 'zustand';

const RV_MODE_KEY = 'openclaw-guard-rv-mode';
const THEME_KEY = 'openclaw-guard-theme';

const _initialTheme = () => {
  if (typeof localStorage !== 'undefined') {
    const saved = localStorage.getItem(THEME_KEY);
    if (saved === 'dark' || saved === 'light') return saved;
    if (typeof window !== 'undefined' && window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
      return 'dark';
    }
  }
  return 'light';
};

export const useStore = create((set, get) => ({
  // ── Summary data ──
  summary: {},
  loading: true,
  _summaryHash: '',

  // ── Theme ──
  theme: _initialTheme(),

  // ── View state (replaces state.view — now handled by preact-router) ──
  actionFilter: 'pending_approval',
  pages: { actions: 1 },
  pageSize: 8,

  // ── Toast ──
  toast: null,

  // ── Scan ──
  scan: {
    running: false,
    progress: 0,
    phase: '',
    result: null,
    selected: 'config',
  },

  // ── Search ──
  rulesSearch: '',

  // ── RV ──
  rvMode: (typeof localStorage !== 'undefined'
    ? localStorage.getItem(RV_MODE_KEY) || 'on'
    : 'on') === 'on',
  rvStatus: null,

  // ── Setters ──

  setSummary: (summary) =>
    set((s) => {
      const h = summary?.actions
        ? JSON.stringify({
            actions: summary.actions,
            sync: summary.sync || {},
            skills: summary.skills || {},
            channels: summary.channels || {},
            preferences: summary.preferences || {},
          })
        : '0';
      return h !== s._summaryHash || s.loading
        ? { summary, loading: false, _summaryHash: h }
        : {};
    }),

  upsertAction: (action) => set((s) => {
    const current = s.summary.actions || {};
    const items = [...(current.items || [])];
    const index = items.findIndex((item) => item.action_id === action.action_id);
    if (index >= 0) items[index] = { ...items[index], ...action };
    else items.unshift(action);
    return { loading: false, summary: { ...s.summary, actions: { ...current, items } } };
  }),

  setLoading: (loading) => set({ loading }),

  setActionFilter: (f) => set({ actionFilter: f, pages: { ...get().pages, actions: 1 } }),

  setPage: (pk, n) =>
    set((s) => {
      const cur = (s.pages[pk] || 1) + n;
      return { pages: { ...s.pages, [pk]: Math.max(1, cur) } };
    }),

  setScan: (scan) => set({ scan: { ...get().scan, ...scan } }),

  setRulesSearch: (q) => set({ rulesSearch: q }),

  setRvMode: (on) => {
    const v = !!on;
    if (typeof localStorage !== 'undefined') {
      localStorage.setItem(RV_MODE_KEY, v ? 'on' : 'off');
    }
    set({ rvMode: v });
  },

  setTheme: (t) => {
    const v = t === 'dark' ? 'dark' : 'light';
    if (typeof localStorage !== 'undefined') {
      localStorage.setItem(THEME_KEY, v);
    }
    if (typeof document !== 'undefined') {
      document.documentElement.setAttribute('data-theme', v);
    }
    set({ theme: v });
  },

  toggleTheme: () => set((s) => {
    const v = s.theme === 'dark' ? 'light' : 'dark';
    if (typeof localStorage !== 'undefined') {
      localStorage.setItem(THEME_KEY, v);
    }
    if (typeof document !== 'undefined') {
      document.documentElement.setAttribute('data-theme', v);
    }
    return { theme: v };
  }),

  setRvStatus: (rvStatus) => set({ rvStatus }),

  showToast: (msg) => {
    set({ toast: msg });
    clearTimeout(get()._toastTimer);
    const timer = setTimeout(() => set({ toast: null }), 3000);
    set({ _toastTimer: timer });
  },

  // ── Optimistic action updates ──

  optimisticUpdate: (id, status) =>
    set((s) => {
      const a = s.summary.actions || {};
      const items = (a.items || []).map((i) =>
        i.action_id === id ? { ...i, status } : i,
      );
      return { summary: { ...s.summary, actions: { ...a, items } } };
    }),

  setActionLoading: (id, loading) =>
    set((s) => {
      const a = s.summary.actions || {};
      const items = (a.items || []).map((i) =>
        i.action_id === id ? { ...i, _loading: loading } : i,
      );
      return { summary: { ...s.summary, actions: { ...a, items } } };
    }),
}));
