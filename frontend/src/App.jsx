import { Component, h } from 'preact';
import { useState } from 'preact/hooks';
import { Router } from 'preact-router';
import { Layout } from './components/Layout';
import { Dashboard } from './pages/Dashboard';

/**
 * 按页面做代码分割：仅 Dashboard 首屏即时加载，其余页面懒加载，
 * 守住「首屏 JS ≤ 20KB gzip」的体积约束。
 */
function lazyPage(load) {
  class LazyPage extends Component {
    constructor(props) {
      super(props);
      this.state = { Page: null };
    }
    componentDidMount() {
      this._mounted = true;
      load().then((Page) => {
        if (this._mounted) this.setState({ Page });
      });
    }
    componentWillUnmount() {
      this._mounted = false;
    }
    render() {
      const { Page } = this.state;
      if (Page) return h(Page, this.props);
      return (
        <div class="loading-wrap">
          <div class="loading-spinner"></div>
        </div>
      );
    }
  }
  return LazyPage;
}

const Actions = lazyPage(() => import('./pages/Actions').then((m) => m.Actions));
const Rules = lazyPage(() => import('./pages/Rules').then((m) => m.Rules));
const Skills = lazyPage(() => import('./pages/Skills').then((m) => m.Skills));
const Settings = lazyPage(() => import('./pages/Settings').then((m) => m.Settings));

export function App() {
  const [currentPath, setCurrentPath] = useState(
    typeof window === 'undefined' ? '/' : (window.location.pathname || '/')
  );

  return (
    <Layout currentPath={currentPath}>
      <Router onChange={(e) => setCurrentPath(e.url || '/')}>
        <Dashboard path="/" />
        <Actions path="/actions" />
        <Rules path="/rules" />
        <Skills path="/skills" />
        <Settings path="/settings" />
      </Router>
    </Layout>
  );
}
