import { Router } from 'preact-router';
import { Layout } from './components/Layout';
import { Dashboard } from './pages/Dashboard';
import { Actions } from './pages/Actions';
import { Rules } from './pages/Rules';
import { Skills } from './pages/Skills';
import { Settings } from './pages/Settings';

export function App() {
  return (
    <Layout>
      <Router>
        <Dashboard path="/" />
        <Actions path="/actions" />
        <Rules path="/rules" />
        <Skills path="/skills" />
        <Settings path="/settings" />
      </Router>
    </Layout>
  );
}
