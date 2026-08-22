import { render } from 'preact';
import { App } from './App';
import { useStore } from './store';

// 首屏前注入主题，避免闪烁（在 React 渲染前同步设置 data-theme）
document.documentElement.setAttribute('data-theme', useStore.getState().theme);

render(<App />, document.getElementById('app'));
