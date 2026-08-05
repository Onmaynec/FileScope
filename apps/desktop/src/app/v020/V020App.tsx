import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Archive, BarChart3, CheckCircle2, CircleHelp, FileSearch, FolderArchive, Globe2,
  Home, Info, Menu, Search, Settings, ShieldCheck, Upload,
} from 'lucide-react';
import { AnalysisSettings } from '../../features/analysis/ui/AnalysisSettings';
import { AnalysisWorkspace } from '../../features/analysis/ui/AnalysisWorkspace';
import { ReportHistory } from '../../features/analysis/ui/ReportHistory';
import { loadAnalysisLimits, loadReports } from '../../features/analysis/model/analysis-storage';
import type { AnalysisLimits, AnalysisReport, ObjectKind } from '../../features/analysis/model/types';
import { useAppPreferences } from '../../shared/hooks/use-app-preferences';
import { bindNativeNavigation, selectLocalObject, syncCloseBehavior } from '../../shared/native/native-bridge';
import { ToastHost, type ToastMessage } from '../../widgets/notifications/ToastHost';

type Page = 'home' | 'scan' | 'links' | 'files' | 'archives' | 'reports' | 'settings' | 'about';

const navigation = [
  ['home', 'Главная', Home],
  ['scan', 'Проверка', Search],
  ['links', 'Ссылки', Globe2],
  ['files', 'Файлы', FileSearch],
  ['archives', 'Архивы', FolderArchive],
  ['reports', 'Отчёты', BarChart3],
  ['settings', 'Настройки', Settings],
] as const;

export function V020App() {
  const { preferences, patchPreferences } = useAppPreferences();
  const [page, setPage] = useState<Page>(() => isPage(preferences.lastPage) ? preferences.lastPage : 'home');
  const [selectedPath, setSelectedPath] = useState('');
  const [limits, setLimits] = useState<AnalysisLimits>(() => loadAnalysisLimits());
  const [systemDark, setSystemDark] = useState(() => window.matchMedia?.('(prefers-color-scheme: dark)').matches ?? true);
  const [toasts, setToasts] = useState<ToastMessage[]>([]);
  const resolvedTheme = preferences.theme === 'system' ? (systemDark ? 'dark' : 'light') : preferences.theme;
  const activeTitle = useMemo(() => navigation.find(([id]) => id === page)?.[1] ?? 'О программе', [page]);

  const navigate = useCallback((next: Page) => {
    setPage(next);
    patchPreferences({ lastPage: next });
  }, [patchPreferences]);

  const pushToast = useCallback((title: string, text?: string) => {
    const id = `${Date.now()}-${Math.random()}`;
    setToasts((current) => [...current, { id, title, text, tone: 'success' }]);
    window.setTimeout(() => setToasts((current) => current.filter((item) => item.id !== id)), 4200);
  }, []);

  const chooseFile = useCallback(async () => {
    const selected = await selectLocalObject(false);
    if (!selected) return;
    setSelectedPath(selected.path);
    navigate('files');
  }, [navigate]);

  useEffect(() => {
    const media = window.matchMedia?.('(prefers-color-scheme: dark)');
    if (!media) return;
    const listener = (event: MediaQueryListEvent) => setSystemDark(event.matches);
    media.addEventListener('change', listener);
    return () => media.removeEventListener('change', listener);
  }, []);

  useEffect(() => {
    void syncCloseBehavior(preferences.closeBehavior);
  }, [preferences.closeBehavior]);

  useEffect(() => {
    let listeners: (() => void)[] = [];
    void bindNativeNavigation((target) => {
      if (isPage(target)) navigate(target);
    }, () => { void chooseFile(); }).then((value) => { listeners = value; });
    return () => listeners.forEach((listener) => listener());
  }, [chooseFile, navigate]);

  const onReport = (report: AnalysisReport) => pushToast('Отчёт сохранён локально', `${report.displayName} · ${report.riskScore}/100`);

  let content = <HomePage navigate={navigate} chooseFile={chooseFile} />;
  if (page === 'scan') content = <AnalysisPage mode="file" limits={limits} onReport={onReport} />;
  if (page === 'links') content = <AnalysisPage mode="url" limits={limits} onReport={onReport} />;
  if (page === 'files') content = <AnalysisPage mode="file" path={selectedPath} limits={limits} onReport={onReport} />;
  if (page === 'archives') content = <AnalysisPage mode="archive" limits={limits} onReport={onReport} />;
  if (page === 'reports') content = <><PageHeader title="Отчёты" text="Результаты реальных локальных проверок. Данные хранятся только на этом устройстве." /><ReportHistory /></>;
  if (page === 'settings') content = <SettingsPage limits={limits} setLimits={setLimits} theme={preferences.theme} setTheme={(theme) => patchPreferences({ theme })} closeBehavior={preferences.closeBehavior} setCloseBehavior={(closeBehavior) => patchPreferences({ closeBehavior })} />;
  if (page === 'about') content = <AboutPage />;

  return <div className={`app theme-${resolvedTheme}`}>
    <aside className={`sidebar ${preferences.sidebarCollapsed ? 'collapsed' : ''}`} aria-label="Основная навигация">
      <button className="brand" onClick={() => navigate('home')}><span className="brand-mark"><ShieldCheck /></span><strong>FileScope</strong></button>
      <nav>{navigation.map(([id, label, Icon]) => <button key={id} title={label} className={`nav-item ${page === id ? 'active' : ''}`} onClick={() => navigate(id)}><Icon /><span>{label}</span></button>)}</nav>
      <div className="sidebar-bottom"><button className="nav-item utility-item" onClick={() => navigate('about')} title="О программе"><CircleHelp /><span>О программе</span></button><small>Версия 0.3.0</small></div>
    </aside>
    <main className="main">
      <header className="titlebar"><button className="icon-button" onClick={() => patchPreferences({ sidebarCollapsed: !preferences.sidebarCollapsed })} aria-label="Свернуть боковую панель"><Menu /></button><strong>{activeTitle}</strong><span className="title-spacer" /><span className="offline-status"><CheckCircle2 />Локальное ядро</span></header>
      <div className="content">{content}</div>
    </main>
    <ToastHost messages={toasts} onDismiss={(id) => setToasts((current) => current.filter((item) => item.id !== id))} />
  </div>;
}

function PageHeader({ title, text }: { title: string; text: string }) {
  return <header className="page-header"><h1>{title}</h1><p>{text}</p></header>;
}

function AnalysisPage({ mode, path, limits, onReport }: { mode: ObjectKind; path?: string; limits: AnalysisLimits; onReport: (report: AnalysisReport) => void }) {
  const title = mode === 'url' ? 'Ссылки' : mode === 'archive' ? 'Архивы' : 'Проверка файлов';
  const text = mode === 'url' ? 'Пассивный разбор выполняется без сети. Активная проверка доступна только после явного согласия.' : mode === 'archive' ? 'ZIP анализируется без извлечения содержимого на диск.' : 'SHA-256, сигнатура типа и PE-структура проверяются без запуска файла.';
  return <><PageHeader title={title} text={text} /><AnalysisWorkspace initialMode={mode} initialPath={path} limits={limits} onReport={onReport} /></>;
}

function HomePage({ navigate, chooseFile }: { navigate: (page: Page) => void; chooseFile: () => Promise<void> }) {
  const reportCount = loadReports().length;
  return <>
    <section className="v020-hero"><div><span className="analysis-kicker">FileScope Core v0.3.0</span><h1>Реальный анализ до запуска</h1><p>Вычисляйте SHA-256, проверяйте типы файлов, PE-структуру, URL и ZIP-архивы локально. Исследуемые объекты не запускаются и не отправляются наружу.</p><div className="button-row"><button className="button button-primary" onClick={() => void chooseFile()}><Upload />Выбрать файл</button><button className="button button-secondary" onClick={() => navigate('links')}><Globe2 />Проверить URL</button></div></div><div className="v020-hero__shield"><ShieldCheck /><span>Local-first</span><strong>0 внешних загрузок файлов</strong></div></section>
    <section className="quick-grid"><button className="action-card" onClick={() => navigate('files')}><FileSearch /><strong>Файлы</strong><span>SHA-256, сигнатуры, PE, импорты и энтропия.</span></button><button className="action-card" onClick={() => navigate('links')}><Globe2 /><strong>URL</strong><span>Пассивный разбор и ручная активная проверка.</span></button><button className="action-card" onClick={() => navigate('archives')}><Archive /><strong>ZIP-архивы</strong><span>Пути, глубина, степень сжатия и вложенные объекты.</span></button><button className="action-card" onClick={() => navigate('reports')}><BarChart3 /><strong>Отчёты</strong><span>{reportCount ? `Сохранено локально: ${reportCount}` : 'История пока пуста.'}</span></button></section>
    <section className="info-banner"><ShieldCheck /><div><strong>Объяснимый риск вместо надписи «безопасно»</strong><span>Каждый уровень риска формируется из конкретных правил, доказательств и рекомендаций. Отсутствие признаков не считается абсолютной гарантией.</span></div></section>
  </>;
}

function SettingsPage({ limits, setLimits, theme, setTheme, closeBehavior, setCloseBehavior }: { limits: AnalysisLimits; setLimits: (limits: AnalysisLimits) => void; theme: 'system' | 'dark' | 'light'; setTheme: (theme: 'system' | 'dark' | 'light') => void; closeBehavior: 'tray' | 'quit'; setCloseBehavior: (value: 'tray' | 'quit') => void }) {
  return <><PageHeader title="Настройки" text="Настройки интерфейса и защитных ограничений сохраняются локально." /><section className="card settings-v020"><h2>Интерфейс и окно</h2><div className="setting-row"><div><strong>Тема</strong><span>Системная, светлая или тёмная.</span></div><select className="input compact" value={theme} onChange={(event) => setTheme(event.target.value as typeof theme)}><option value="system">Системная</option><option value="dark">Тёмная</option><option value="light">Светлая</option></select></div><div className="setting-row"><div><strong>При закрытии окна</strong><span>Крестик скрывает приложение в трей или полностью завершает процесс.</span></div><select className="input compact" value={closeBehavior} onChange={(event) => setCloseBehavior(event.target.value as typeof closeBehavior)}><option value="tray">Сворачивать в трей</option><option value="quit">Закрывать полностью</option></select></div></section><AnalysisSettings value={limits} onChange={setLimits} /></>;
}

function AboutPage() {
  return <><PageHeader title="О программе" text="FileScope v0.3.0 — стабильное обновление lifecycle Windows-приложения." /><section className="card about-v020"><span className="about-logo"><ShieldCheck /></span><div><h2>FileScope 0.3.0</h2><p>Desktop-приложение для предварительной локальной проверки файлов, ссылок и ZIP-архивов до запуска.</p></div><dl className="metadata-grid"><div><dt>Режим</dt><dd>Локальный анализ</dd></div><div><dt>Файлы</dt><dd>SHA-256, magic, PE</dd></div><div><dt>URL</dt><dd>Пассивный + ручной активный</dd></div><div><dt>Архивы</dt><dd>ZIP без извлечения</dd></div></dl><div className="status-banner warning"><Info /><span>FileScope снижает риск, но не гарантирует абсолютную безопасность и не заменяет многоуровневую защиту системы.</span></div></section></>;
}

function isPage(value: string): value is Page {
  return ['home', 'scan', 'links', 'files', 'archives', 'reports', 'settings', 'about'].includes(value);
}
