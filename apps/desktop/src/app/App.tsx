import { useMemo, useState } from 'react';
import {
  Archive, BarChart3, ChevronLeft, FileSearch, FolderArchive, Home, Info, Link2,
  Menu, MonitorCog, PackageOpen, Search, Settings, ShieldAlert, ShieldCheck,
  Trash2, Upload, X,
} from 'lucide-react';
import { demoArchiveTree, demoPrograms, demoReports, type DemoReport, type DemoRisk } from '../mocks/demo-data';

const pages = [
  ['home', 'Главная', Home], ['scan', 'Проверка', Search], ['links', 'Ссылки', Link2],
  ['files', 'Файлы', FileSearch], ['archives', 'Архивы', FolderArchive], ['programs', 'Программы', MonitorCog],
  ['reports', 'Отчёты', BarChart3], ['quarantine', 'Карантин', Archive], ['settings', 'Настройки', Settings],
] as const;

type Page = typeof pages[number][0] | 'result' | 'subscription' | 'about';
type Theme = 'dark' | 'light';

const riskLabels: Record<DemoRisk, string> = {
  noThreatsFound: 'Признаков угрозы не найдено', caution: 'Требуется осторожность',
  highRisk: 'Высокий риск', dangerous: 'Опасный объект',
};

function ModuleUnavailable({ onClose }: { onClose: () => void }) {
  return <div className="dialog-backdrop" role="presentation" onMouseDown={onClose}>
    <section className="dialog" role="dialog" aria-modal="true" aria-labelledby="dialog-title" onMouseDown={(e) => e.stopPropagation()}>
      <button className="icon-button dialog-close" onClick={onClose} aria-label="Закрыть"><X /></button>
      <div className="dialog-icon"><Info /></div>
      <h2 id="dialog-title">Модуль анализа находится в разработке</h2>
      <p>Настоящая проверка пользовательских объектов появится в следующей версии. FileScope не выполнял сканирование и не присваивал объекту фиктивный вердикт.</p>
      <button className="button button-primary" onClick={onClose}>Понятно</button>
    </section>
  </div>;
}

function PageHeader({ title, text }: { title: string; text: string }) {
  return <header className="page-header"><h1>{title}</h1><p>{text}</p></header>;
}

function DemoBadge() { return <span className="badge">Демонстрационные данные</span>; }

function Dropzone({ openUnavailable }: { openUnavailable: () => void }) {
  const [dragging, setDragging] = useState(false);
  return <button className={`dropzone ${dragging ? 'dropzone--active' : ''}`} onClick={openUnavailable}
    onDragOver={(e) => { e.preventDefault(); setDragging(true); }} onDragLeave={() => setDragging(false)}
    onDrop={(e) => { e.preventDefault(); setDragging(false); openUnavailable(); }}>
    <Upload size={44} aria-hidden="true" /><strong>Перетащите файл, архив или папку</strong>
    <span>Поддержка EXE, MSI, ZIP, RAR, 7Z, CRX, XPI и других объектов появится с аналитическим модулем.</span>
    <span className="button button-primary">Выбрать файл</span>
  </button>;
}

function HomePage({ navigate, unavailable }: { navigate: (p: Page) => void; unavailable: () => void }) {
  const cards: [Page, string, string, typeof Link2][] = [
    ['links', 'Проверить ссылку', 'Пассивно разобрать адрес до открытия.', Link2],
    ['files', 'Проверить файл', 'Выбрать объект на устройстве.', FileSearch],
    ['archives', 'Проверить архив', 'Просмотреть дерево содержимого.', PackageOpen],
    ['programs', 'Проверить программу', 'Выбрать приложение из списка.', MonitorCog],
  ];
  return <><PageHeader title="Проверка ссылок, файлов и архивов до запуска" text="Выберите объект или перетащите его в окно FileScope." />
    <Dropzone openUnavailable={unavailable} />
    <section className="quick-grid" aria-label="Быстрые действия">{cards.map(([page, title, text, Icon]) =>
      <button className="action-card" key={page} onClick={() => navigate(page)}><Icon /><strong>{title}</strong><span>{text}</span></button>)}</section>
    <div className="info-banner"><ShieldCheck /><div><strong>Локальный подход к приватности</strong><span>Первая версия не отправляет файлы и ссылки во внешние сервисы и работает без интернета.</span></div></div></>;
}

function ScanPage({ unavailable }: { unavailable: () => void }) {
  const [tab, setTab] = useState('Файл');
  return <><PageHeader title="Проверка" text="Универсальный выбор объекта для будущих модулей анализа." />
    <div className="tabs">{['Файл', 'Ссылка', 'Архив', 'Программа', 'Расширение'].map(t => <button className={tab === t ? 'active' : ''} onClick={() => setTab(t)} key={t}>{t}</button>)}</div>
    <section className="card form-card"><h2>{tab}</h2>{tab === 'Ссылка' ? <input className="input" placeholder="https://example.com/path" /> : <Dropzone openUnavailable={unavailable} />}
      <div className="button-row"><button className="button button-primary" onClick={unavailable}>Начать проверку</button><button className="button button-secondary" onClick={unavailable}>Выбрать объект</button></div></section></>;
}

function LinksPage({ unavailable }: { unavailable: () => void }) {
  const [url, setUrl] = useState('https://example.com/download?source=demo');
  return <><PageHeader title="Ссылки" text="Пассивный анализ не открывает страницу и не выполняет сетевой запрос." />
    <section className="card"><label className="field-label" htmlFor="url">Адрес ссылки</label><div className="input-row"><input id="url" className="input" value={url} onChange={e => setUrl(e.target.value.trimStart())}/><button className="icon-button" onClick={() => setUrl('')} aria-label="Очистить"><X /></button></div>
      <div className="button-row"><button className="button button-primary" onClick={unavailable}>Пассивный анализ</button><button className="button button-secondary" onClick={unavailable}>Активная проверка · Скоро</button></div></section>
    <section className="card result-preview"><DemoBadge /><h2>Пример результата ссылки</h2><dl className="metadata-grid"><div><dt>Домен</dt><dd>example.com</dd></div><div><dt>Протокол</dt><dd>HTTPS</dd></div><div><dt>Punycode</dt><dd>Не обнаружен</dd></div><div><dt>Редиректы</dt><dd>1 демонстрационный</dd></div></dl></section></>;
}

function FilesPage({ navigate, unavailable }: { navigate: (p: Page) => void; unavailable: () => void }) {
  return <><PageHeader title="Файлы" text="В следующих версиях здесь появится статический анализ файлов без их запуска." /><Dropzone openUnavailable={unavailable}/>
    <section className="card selected-object"><FileSearch/><div><strong>example-safe.exe</strong><span>Встроенный демонстрационный объект · 4,2 МБ</span></div><DemoBadge/><button className="button button-secondary" onClick={() => navigate('result')}>Посмотреть пример отчёта</button></section></>;
}

function ArchivesPage({ unavailable }: { unavailable: () => void }) {
  return <><PageHeader title="Архивы" text="Будущий рекурсивный анализ ZIP, RAR и 7Z с защитой от архивных бомб и path traversal." />
    <section className="two-column"><div className="card"><Dropzone openUnavailable={unavailable}/><label className="field-label">Пароль архива</label><input className="input" type="password" placeholder="Не сохраняется"/><button className="button button-primary" onClick={unavailable}>Проверить архив</button></div>
    <div className="card"><DemoBadge/><h2>Дерево архива</h2><pre className="tree">{demoArchiveTree.map((line, i) => <span className={i === 4 ? 'danger-line' : ''} key={line}>{line}{'\n'}</span>)}</pre></div></section></>;
}

function ProgramsPage({ unavailable }: { unavailable: () => void }) {
  const [query, setQuery] = useState(''); const programs = demoPrograms.filter(p => `${p.name} ${p.publisher}`.toLowerCase().includes(query.toLowerCase()));
  return <><PageHeader title="Программы" text="Реальным установленным программам не присваиваются фиктивные уровни риска." />
    <div className="toolbar"><input className="input" placeholder="Поиск по названию или издателю" value={query} onChange={e => setQuery(e.target.value)}/><select className="input"><option>По названию</option><option>По издателю</option><option>По дате установки</option></select></div>
    <div className="program-list">{programs.map(p => <section className="card program-card" key={p.id}><div className="program-icon"><MonitorCog/></div><div><strong>{p.name}</strong><span>{p.publisher} · {p.version} · {p.installed}</span></div><DemoBadge/><button className="button button-secondary" onClick={unavailable}>Выбрать</button></section>)}</div></>;
}

function ReportsPage({ openReport }: { openReport: (r: DemoReport) => void }) {
  return <><PageHeader title="Отчёты" text="В первой версии отображаются только встроенные демонстрационные отчёты." /><div className="report-grid">{demoReports.map(r => <button className="card report-card" key={r.id} onClick={() => openReport(r)}><DemoBadge/><span className={`risk-dot risk-${r.risk}`}/><strong>{r.name}</strong><span>{r.kind}</span><b>{riskLabels[r.risk]}</b></button>)}</div></>;
}

function ResultPage({ report, quarantine }: { report: DemoReport; quarantine: () => void }) {
  return <><PageHeader title="Результат проверки" text="Все сведения ниже вымышлены и используются только для демонстрации интерфейса." />
    <section className={`risk-summary risk-${report.risk}`}><DemoBadge/><ShieldAlert size={48}/><div><h2>{riskLabels[report.risk]}</h2><p>{report.summary}</p><strong>{report.name}</strong></div><button className="button button-primary" onClick={quarantine}>Поместить в mock-карантин</button></section>
    <div className="two-column"><section className="card"><h2>Рекомендация</h2><p>{report.recommendation}</p></section><section className="card"><h2>Причины обнаружения</h2>{report.indicators.map(i => <div className="indicator" key={i}><ShieldAlert/><span>{i}</span></div>)}</section></div>
    <section className="card"><h2>Метаданные</h2><dl className="metadata-grid"><div><dt>Тип</dt><dd>{report.kind}</dd></div><div><dt>Время</dt><dd>05.08.2026 02:10</dd></div><div><dt>Источник</dt><dd>Встроенный mock-набор</dd></div><div><dt>isDemo</dt><dd>true</dd></div></dl></section></>;
}

function QuarantinePage({ items, clear }: { items: string[]; clear: (name: string) => void }) {
  return <><PageHeader title="Карантин" text="Экран работает только с локальным mock-состоянием. Реальные файлы не изменяются." /><div className="info-banner warning"><Info/><div><strong>Демо-режим</strong><span>В этой версии карантин не перемещает и не шифрует файлы.</span></div></div>
    {items.length === 0 ? <section className="empty card"><Archive size={44}/><h2>Карантин пуст</h2><p>Добавьте демонстрационный объект со страницы результата.</p></section> : items.map(name => <section className="card selected-object" key={name}><Archive/><div><strong>{name}</strong><span>Помещён в mock-карантин</span></div><button className="icon-button" onClick={() => clear(name)} aria-label="Удалить запись"><Trash2/></button></section>)}</>;
}

function SettingsPage({ theme, setTheme, developer, setDeveloper }: { theme: Theme; setTheme: (t: Theme) => void; developer: boolean; setDeveloper: (v: boolean) => void }) {
  return <><PageHeader title="Настройки" text="Настройки сохраняются локально в текущем прототипе интерфейса." />
    <section className="settings-layout"><nav className="settings-nav">{['Общие','Внешний вид','Поведение окна','Проверка','Приватность','Исключения','Режим разработчика','Обновления','Подписка','О программе'].map(x => <button key={x}>{x}</button>)}</nav>
    <div className="settings-content"><section className="card"><h2>Внешний вид</h2><div className="setting-row"><div><strong>Тема интерфейса</strong><span>Тёмная тема является основной.</span></div><select className="input" value={theme} onChange={e => setTheme(e.target.value as Theme)}><option value="dark">Тёмная</option><option value="light">Светлая</option></select></div></section>
    <section className="card"><h2>Режим разработчика</h2><div className="setting-row"><div><strong>Технические данные</strong><span>Отображает хеши, правила и сырые mock-события.</span></div><button className={`switch ${developer ? 'on' : ''}`} role="switch" aria-checked={developer} onClick={() => setDeveloper(!developer)}><span/></button></div>{developer && <pre className="code-block">ruleId: FS-DEMO-001{`\n`}engine: mock{`\n`}networkAccess: false</pre>}</section>
    <section className="card"><h2>Обновления</h2><div className="setting-row"><div><strong>Текущая версия</strong><span>0.1.0</span></div><button className="button button-secondary">Проверить обновления</button></div></section></div></section></>;
}

export function App() {
  const [page, setPage] = useState<Page>('home'); const [collapsed, setCollapsed] = useState(false);
  const [unavailable, setUnavailable] = useState(false); const [theme, setTheme] = useState<Theme>('dark');
  const [developer, setDeveloper] = useState(false); const [selectedReport, setSelectedReport] = useState(demoReports[3]);
  const [quarantine, setQuarantine] = useState<string[]>([]); const activeTitle = useMemo(() => pages.find(p => p[0] === page)?.[1] ?? 'Результат', [page]);
  const openReport = (r: DemoReport) => { setSelectedReport(r); setPage('result'); };
  const addQuarantine = () => { setQuarantine(q => q.includes(selectedReport.name) ? q : [...q, selectedReport.name]); setPage('quarantine'); };

  let content = <HomePage navigate={setPage} unavailable={() => setUnavailable(true)}/>;
  if (page === 'scan') content = <ScanPage unavailable={() => setUnavailable(true)}/>;
  if (page === 'links') content = <LinksPage unavailable={() => setUnavailable(true)}/>;
  if (page === 'files') content = <FilesPage navigate={setPage} unavailable={() => setUnavailable(true)}/>;
  if (page === 'archives') content = <ArchivesPage unavailable={() => setUnavailable(true)}/>;
  if (page === 'programs') content = <ProgramsPage unavailable={() => setUnavailable(true)}/>;
  if (page === 'reports') content = <ReportsPage openReport={openReport}/>;
  if (page === 'result') content = <ResultPage report={selectedReport} quarantine={addQuarantine}/>;
  if (page === 'quarantine') content = <QuarantinePage items={quarantine} clear={name => setQuarantine(q => q.filter(x => x !== name))}/>;
  if (page === 'settings') content = <SettingsPage theme={theme} setTheme={setTheme} developer={developer} setDeveloper={setDeveloper}/>;

  return <div className={`app theme-${theme}`}><aside className={`sidebar ${collapsed ? 'collapsed' : ''}`} aria-label="Основная навигация">
    <button className="brand" onClick={() => setPage('home')}><span className="brand-mark"><ShieldCheck/></span><strong>FileScope</strong></button>
    <nav>{pages.map(([id, label, Icon]) => <button key={id} title={label} className={`nav-item ${page === id ? 'active' : ''}`} onClick={() => setPage(id)}><Icon/><span>{label}</span></button>)}</nav>
    <div className="sidebar-bottom"><button className="subscription-card" onClick={() => setUnavailable(true)}><strong>FileScope Free</strong><span>Перейти на Pro</span></button><small>Версия 0.1.0</small></div>
  </aside><main className="main"><header className="titlebar"><button className="icon-button" onClick={() => setCollapsed(!collapsed)} aria-label="Свернуть боковую панель"><Menu/></button>{page === 'result' && <button className="icon-button" onClick={() => setPage('reports')} aria-label="Назад"><ChevronLeft/></button>}<strong>{activeTitle}</strong><span className="title-spacer"/><span className="offline-status">● Без подключения к сети</span></header><div className="content">{content}</div></main>{unavailable && <ModuleUnavailable onClose={() => setUnavailable(false)}/>}</div>;
}
