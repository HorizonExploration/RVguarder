import { create } from 'zustand';

const RV_MODE_KEY = 'openclaw-guard-rv-mode';

export const useStore = create((set, get) => ({
  // ── Summary data ──
  summary: {},
  loading: true,
  _summaryHash: '',

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
        ? JSON.stringify(summary.actions).length + '_' + ((summary.actions.items || []).length)
        : '0';
      return h !== s._summaryHash || s.loading
        ? { summary, loading: false, _summaryHash: h }
        : {};
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
