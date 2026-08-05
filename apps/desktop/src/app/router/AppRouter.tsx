import { HashRouter, Route, Routes } from 'react-router-dom';
import { V020App } from '../v020/V020App';

export function AppRouter() {
  return (
    <HashRouter>
      <Routes>
        <Route path="*" element={<V020App />} />
      </Routes>
    </HashRouter>
  );
}
