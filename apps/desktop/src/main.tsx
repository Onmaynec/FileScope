import React from 'react';
import ReactDOM from 'react-dom/client';
import './shared/lib/polyfills';
import { AppRouter } from './app/router/AppRouter';
import './shared/styles/global.css';
import './shared/styles/motion.css';
import './shared/styles/motion-tuning.css';
import './shared/styles/v020.css';
import './shared/styles/queue.css';
import './shared/styles/light-theme-contrast.css';

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <AppRouter />
  </React.StrictMode>,
);
