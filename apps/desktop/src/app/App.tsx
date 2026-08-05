import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Archive, BarChart3, ChevronLeft, FileSearch, FolderArchive, Home, Info, Link2,
  Menu, MonitorCog, PackageOpen, Search, Settings, ShieldAlert, ShieldCheck,
  Trash2, Upload, X, RotateCcw, Plus, Crown, CircleHelp, Copy, CheckCircle2,
} from 'lucide-react';
import { z } from 'zod';
import { demoArchiveTree, demoPrograms, demoReports, type DemoReport, type DemoRisk } from '../mocks/demo-data';
import { AboutPage } from '../pages/about/AboutPage';
import { SubscriptionPage } from '../pages/subscription/SubscriptionPage';
import { useAppPreferences } from '../shared/hooks/use-app-preferences';
import { bindCloseBehavior, bindNativeNavigation, selectLocalObject, type SelectedObject } from '../shared/native/native-bridge';
import type { CloseBehavior, ThemePreference } from '../shared/services/settings-service';
import { Onboarding } from '../widgets/onboarding/Onboarding';
import { ToastHost, type ToastMessage, type ToastTone } from '../widgets/notifications/ToastHost';

const pages = [
  ['home', 'Главная', Home], ['scan', 'Проверка', Search], ['links', 'Ссылки', Link2],
  ['files', 'Файлы', FileSearch], ['archives', 'Архивы', FolderArchive], ['programs', 'Программы', MonitorCog],
  ['reports', 'Отчёты', BarChart3], ['quarantine', 'Карантин', Archive], ['settings', 'Настройки', Settings],
] as const;

type NavigationPage = typeof pages[number][0];
type Page = NavigationPage | 'result' | 'subscription' | 'about';
type DialogKind = 'unavailable' | 'developer' | 'reset' | 'terms' | 'active-url' | null;
type ResultTab = 'overview' | 'reasons' | 'behavior' | 'network' | 'metadata' | 'related' | 'technical';

const riskLabels: Record<DemoRisk, string> = {
  noThreatsFound: 'Признаков угрозы не найдено',
  caution: 'Требуется осторожность',
  highRisk: 'Высокий риск',
  dangerous: 'Опасный объект',
};

const urlSchema = z.string().trim().url('Введите корректный URL').refine((value) => {
  const protocol = new URL(value).protocol;
  return protocol === 'http:' || protocol === 'https:';
}, 'Поддерживаются только HTTP- и HTTPS-ссылки');

function isPage(value: string): value is Page {
  return [...pages.map(([id]) => id), 'result', 'subscription', 'about'].includes(value as Page);
}

function Dialog({ kind, onClose, onConfirm }: { kind: Exclude<DialogKind, null>; onClose: () => void; onConfirm: () => void }) {
  const content = {
    unavailable: {
      title: 'Модуль анализа находится в разработке',
      text: 'Настоящая проверка пользовательских объектов появится в следующей версии. FileScope не выполнял сканирование и не присваивал объекту фиктивный вердикт.',
      confirm: 'Понятно',
    },
    developer: {
      title: 'Включить режим разработчика?',
      text: 'Режим разработчика отображает технические mock-данные, предназначенные для опытных пользователей.',
      confirm: 'Включить',
    },
    reset: {
      title: 'Сбросить настройки?',
      text: 'Будут сброшены тема, поведение окна, исключения, onboarding и локальное mock-состояние. Реальные файлы не затрагиваются.',
      confirm: 'Сбросить',
    },
    terms: {
      title: 'Условия использования',
      text: 'FileScope 0.1.0 является демонстрационной UI-версией без аналитического ядра. Приложение не гарантирует абсолютную безопасность и не заменяет комплексную защиту системы.',
      confirm: 'Понятно',
    },
    'active-url': {
      title: 'Активная проверка URL',
      text: 'В будущей версии активная проверка выполнит сетевое обращение. Сайт сможет увидеть IP-адрес пользователя. Такой анализ будет запускаться только вручную.',
      confirm: 'Понятно',
    },
  }[kind];

  return (
    <div className="dialog-backdrop" role="presentation" onMouseDown={onClose}>
      <section className="dialog" role="dialog" aria-modal="true" aria-labelledby="dialog-title" onMouseDown={(event) => event.stopPropagation()}>
        <button className="icon-button dialog-close" onClick={onClose} aria-label="Закрыть"><X /></button>
        <div className="dialog-icon"><Info /></div>
        <h2 id="dialog-title">{content.title}</h2>
        <p>{content.text}</p>
        <div className="dialog-actions">
          {kind === 'developer' || kind === 'reset' ? <button className="button button-secondary" onClick={onClose}>Отмена</button> : null}
          <button className={`button ${kind === 'reset' ? 'button-danger' : 'button-primary'}`} onClick={onConfirm}>{content.confirm}</button>
        </div>
      </section>
    </div>
  );
}

function PageHeader({ title, text }: { title: string; text: string }) {
  return <header className="page-header"><h1>{title}</h1><p>{text}</p></header>;
}

function DemoBadge() {
  return <span className="badge">Демонстрационные данные</span>;
}

function Dropzone({ onSelect, selected }: { onSelect: () => void; selected?: SelectedObject | null }) {
  const [dragging, setDragging] = useState(false);
  return (
    <button
      className={`dropzone ${dragging ? 'dropzone--active' : ''}`}
      onClick={onSelect}
      onDragOver={(event) => { event.preventDefault(); setDragging(true); }}
      onDragLeave={() => setDragging(false)}
      onDrop={(event) => { event.preventDefault(); setDragging(false); onSelect(); }}
    >
      <Upload size={44} aria-hidden="true" />
      <strong>{selected ? selected.displayName : 'Перетащите файл, архив или папку'}</strong>
      <span>{selected ? selected.path : 'Поддержка EXE, MSI, ZIP, RAR, 7Z, CRX, XPI и других объектов появится с аналитическим модулем.'}</span>
      <span className="button button-primary">{selected ? 'Выбрать другой объект' : 'Выбрать файл'}</span>
    </button>
  );
}

function HomePage({ navigate, selectObject }: { navigate: (page: Page) => void; selectObject: () => void }) {
  const cards: [Page, string, string, typeof Link2][] = [
    ['links', 'Проверить ссылку', 'Пассивно разобрать адрес до открытия.', Link2],
    ['files', 'Проверить файл', 'Выбрать объект на устройстве.', FileSearch],
    ['archives', 'Проверить архив', 'Просмотреть дерево содержимого.', PackageOpen],
    ['programs', 'Проверить программу', 'Выбрать приложение из списка.', MonitorCog],
  ];
  return <><PageHeader title="Проверка ссылок, файлов и архивов до запуска" text="Выберите объект или перетащите его в окно FileScope." />
    <Dropzone onSelect={selectObject} />
    <section className="quick-grid" aria-label="Быстрые действия">{cards.map(([page, title, text, Icon]) =>
      <button className="action-card" key={page} onClick={() => navigate(page)}><Icon /><strong>{title}</strong><span>{text}</span></button>)}</section>
    <div className="info-banner"><ShieldCheck /><div><strong>Локальный подход к приватности</strong><span>Первая версия не отправляет файлы и ссылки во внешние сервисы и работает без интернета.</span></div></div></>;
}

function ScanPage({ selectObject, unavailable }: { selectObject: () => void; unavailable: () => void }) {
  const [tab, setTab] = useState('Файл');
  const [archivePassword, setArchivePassword] = useState('');
  return <><PageHeader title="Проверка" text="Универсальный выбор объекта для будущих модулей анализа." />
    <div className="tabs" role="tablist">{['Файл', 'Ссылка', 'Архив', 'Программа', 'Расширение'].map((item) => <button role="tab" aria-selected={tab === item} className={tab === item ? 'active' : ''} onClick={() => setTab(item)} key={item}>{item}</button>)}</div>
    <section className="card form-card"><h2>{tab}</h2>
      {tab === 'Ссылка' ? <input className="input" placeholder="https://example.com/path" aria-label="Адрес ссылки" /> : <Dropzone onSelect={selectObject} />}
      {tab === 'Архив' && <><label className="field-label" htmlFor="scan-password">Пароль архива</label><input id="scan-password" className="input" type="password" value={archivePassword} onChange={(event) => setArchivePassword(event.target.value)} placeholder="Пароль не сохраняется" autoComplete="off" /></>}
      <div className="button-row"><button className="button button-primary" onClick={unavailable}>Начать проверку</button><button className="button button-secondary" onClick={selectObject}>Выбрать объект</button></div>
    </section></>;
}

function LinksPage({ unavailable, showActiveWarning }: { unavailable: () => void; showActiveWarning: () => void }) {
  const [url, setUrl] = useState('https://example.com/download?source=demo');
  const [error, setError] = useState('');
  const passiveAnalysis = () => {
    const result = urlSchema.safeParse(url);
    if (!result.success) {
      setError(result.error.issues[0]?.message ?? 'Некорректная ссылка');
      return;
    }
    setUrl(result.data);
    setError('');
    unavailable();
  };
  return <><PageHeader title="Ссылки" text="Пассивный анализ не открывает страницу и не выполняет сетевой запрос." />
    <section className="card"><label className="field-label" htmlFor="url">Адрес ссылки</label><div className="input-row"><input id="url" className={`input ${error ? 'input-error' : ''}`} value={url} onChange={(event) => { setUrl(event.target.value.trimStart()); setError(''); }} aria-describedby={error ? 'url-error' : undefined} /><button className="icon-button" onClick={() => { setUrl(''); setError(''); }} aria-label="Очистить"><X /></button></div>
      {error && <span className="field-error" id="url-error">{error}</span>}
      <div className="button-row"><button className="button button-primary" onClick={passiveAnalysis}>Пассивный анализ</button><button className="button button-secondary" onClick={showActiveWarning}>Активная проверка · Скоро</button></div></section>
    <section className="card result-preview"><DemoBadge /><h2>Пример результата ссылки</h2><dl className="metadata-grid"><div><dt>Исходный URL</dt><dd>https://example.com/download?source=demo</dd></div><div><dt>Домен</dt><dd>example.com</dd></div><div><dt>Протокол</dt><dd>HTTPS</dd></div><div><dt>Punycode</dt><dd>Не обнаружен</dd></div><div><dt>Порт</dt><dd>443</dd></div><div><dt>Редиректы</dt><dd>1 демонстрационный</dd></div><div><dt>Трекеры</dt><dd>0</dd></div><div><dt>Риск</dt><dd>Требуется осторожность</dd></div></dl></section></>;
}

function FilesPage({ navigate, selectObject, selected }: { navigate: (page: Page) => void; selectObject: () => void; selected: SelectedObject | null }) {
  return <><PageHeader title="Файлы" text="В следующих версиях здесь появится статический анализ файлов без их запуска." /><Dropzone onSelect={selectObject} selected={selected} />
    <section className="card selected-object"><FileSearch /><div><strong>{selected?.displayName ?? 'example-safe.exe'}</strong><span>{selected ? selected.path : 'Встроенный демонстрационный объект · 4,2 МБ'}</span></div>{selected ? <span className="badge neutral">Выбранный объект не анализировался</span> : <DemoBadge />}<button className="button button-secondary" onClick={() => navigate('result')}>Посмотреть пример отчёта</button></section></>;
}

function ArchivesPage({ selectObject, unavailable }: { selectObject: () => void; unavailable: () => void }) {
  const [password, setPassword] = useState('');
  return <><PageHeader title="Архивы" text="Будущий рекурсивный анализ ZIP, RAR и 7Z с защитой от архивных бомб и path traversal." />
    <section className="two-column"><div className="card"><Dropzone onSelect={selectObject} /><label className="field-label" htmlFor="archive-password">Пароль архива</label><input id="archive-password" className="input" type="password" value={password} onChange={(event) => setPassword(event.target.value)} placeholder="Не сохраняется" autoComplete="off" /><p className="helper-text">Пароль используется только в текущей форме и удаляется после закрытия приложения.</p><button className="button button-primary" onClick={unavailable}>Проверить архив</button></div>
    <div className="card"><DemoBadge /><h2>Дерево архива</h2><pre className="tree">{demoArchiveTree.map((line, index) => <span className={index === 4 ? 'danger-line' : ''} key={line}>{line}{'\n'}</span>)}</pre><div className="status-banner warning"><ShieldAlert /><span>Двойное расширение может скрывать исполняемый файл.</span></div></div></section></>;
}

function ProgramsPage({ unavailable }: { unavailable: () => void }) {
  const [query, setQuery] = useState('');
  const [sort, setSort] = useState('name');
  const programs = useMemo(() => demoPrograms
    .filter((program) => `${program.name} ${program.publisher}`.toLowerCase().includes(query.toLowerCase()))
    .toSorted((left, right) => sort === 'publisher' ? left.publisher.localeCompare(right.publisher) : left.name.localeCompare(right.name)), [query, sort]);
  return <><PageHeader title="Программы" text="Реальным установленным программам не присваиваются фиктивные уровни риска." />
    <div className="toolbar"><input className="input" placeholder="Поиск по названию или издателю" value={query} onChange={(event) => setQuery(event.target.value)} /><select className="input" value={sort} onChange={(event) => setSort(event.target.value)} aria-label="Сортировка"><option value="name">По названию</option><option value="publisher">По издателю</option></select></div>
    <div className="program-list">{programs.map((program) => <section className="card program-card" key={program.id}><div className="program-icon"><MonitorCog /></div><div><strong>{program.name}</strong><span>{program.publisher} · {program.version} · {program.installed}</span></div><DemoBadge /><button className="button button-secondary" onClick={unavailable}>Выбрать</button><button className="text-button" onClick={unavailable}>Подробнее</button></section>)}</div></>;
}

function ReportsPage({ openReport }: { openReport: (report: DemoReport) => void }) {
  const [query, setQuery] = useState('');
  const [risk, setRisk] = useState('all');
  const reports = demoReports.filter((report) => report.name.toLowerCase().includes(query.toLowerCase()) && (risk === 'all' || report.risk === risk));
  return <><PageHeader title="Отчёты" text="В первой версии отображаются только встроенные демонстрационные отчёты." />
    <div className="info-banner warning"><Info /><div><strong>Демонстрационный режим</strong><span>История реальных проверок не ведётся.</span></div></div>
    <div className="toolbar reports-toolbar"><input className="input" placeholder="Поиск отчёта" value={query} onChange={(event) => setQuery(event.target.value)} /><select className="input" value={risk} onChange={(event) => setRisk(event.target.value)} aria-label="Фильтр риска"><option value="all">Все уровни риска</option><option value="noThreatsFound">Без признаков угрозы</option><option value="caution">Осторожность</option><option value="highRisk">Высокий риск</option><option value="dangerous">Опасный объект</option></select></div>
    {reports.length === 0 ? <section className="empty card"><Search /><h2>Отчёты не найдены</h2><p>Измените строку поиска или фильтр риска.</p></section> : <div className="report-grid">{reports.map((report) => <button className="card report-card" key={report.id} onClick={() => openReport(report)}><DemoBadge /><span className={`risk-dot risk-${report.risk}`} /><strong>{report.name}</strong><span>{report.kind}</span><b>{riskLabels[report.risk]}</b></button>)}</div>}</>;
}

function ResultPage({ report, developerMode, quarantine, mockAction, addExclusion }: { report: DemoReport; developerMode: boolean; quarantine: () => void; mockAction: (title: string) => void; addExclusion: () => void }) {
  const [tab, setTab] = useState<ResultTab>('overview');
  const tabs: [ResultTab, string][] = [['overview', 'Обзор'], ['reasons', 'Причины'], ['behavior', 'Поведение'], ['network', 'Сеть'], ['metadata', 'Метаданные'], ['related', 'Связанные объекты']];
  if (developerMode) tabs.push(['technical', 'Технические данные']);
  return <><PageHeader title="Результат проверки" text="Все сведения ниже вымышлены и используются только для демонстрации интерфейса." />
    <section className={`risk-summary risk-${report.risk}`}><DemoBadge /><ShieldAlert size={48} /><div><h2>{riskLabels[report.risk]}</h2><p>{report.summary}</p><strong>{report.name}</strong></div></section>
    <div className="result-actions"><button className="button button-danger" onClick={() => mockAction('Демонстрационный объект удалён')}>Удалить</button><button className="button button-secondary" onClick={() => mockAction('Демонстрационный объект заблокирован')}>Заблокировать</button><button className="button button-primary" onClick={quarantine}>В карантин</button><button className="button button-secondary" onClick={addExclusion}>Добавить в исключения</button><button className="text-button" onClick={() => mockAction('Объект отмечен как доверенный')}>Я доверяю объекту</button></div>
    <div className="tabs result-tabs" role="tablist">{tabs.map(([id, label]) => <button key={id} role="tab" aria-selected={tab === id} className={tab === id ? 'active' : ''} onClick={() => setTab(id)}>{label}</button>)}</div>
    {tab === 'overview' && <div className="two-column"><section className="card"><h2>Рекомендация</h2><p>{report.recommendation}</p></section><section className="card"><h2>Ключевые причины</h2>{report.indicators.slice(0, 3).map((indicator) => <div className="indicator" key={indicator}><ShieldAlert /><span>{indicator}</span></div>)}</section></div>}
    {tab === 'reasons' && <section className="card"><h2>Причины обнаружения</h2>{report.indicators.map((indicator) => <div className="indicator indicator-detailed" key={indicator}><ShieldAlert /><div><strong>{indicator}</strong><span>Обнаружены эвристические признаки. Требуется дополнительная проверка.</span></div><span className="badge neutral">Эвристика</span></div>)}</section>}
    {tab === 'behavior' && <section className="card"><h2>Поведение</h2><div className="status-banner warning"><ShieldAlert /><span>Mock: объект может обращаться к профилям браузеров и механизмам автозапуска.</span></div></section>}
    {tab === 'network' && <section className="card"><h2>Сетевые события</h2><p className="helper-text">Внешние соединения не выполнялись. Ниже показана только демонстрационная запись.</p><div className="table-row"><span>203.0.113.10</span><span>443 / HTTPS</span><span className="badge">Mock</span></div></section>}
    {tab === 'metadata' && <section className="card"><h2>Метаданные</h2><dl className="metadata-grid"><div><dt>Тип</dt><dd>{report.kind}</dd></div><div><dt>Время</dt><dd>05.08.2026 02:10</dd></div><div><dt>Источник</dt><dd>Встроенный mock-набор</dd></div><div><dt>isDemo</dt><dd>true</dd></div><div><dt>SHA-256</dt><dd>demo00000000000000000000000000000000</dd></div><div><dt>Подпись</dt><dd>Демонстрационная</dd></div></dl></section>}
    {tab === 'related' && <section className="empty card"><PackageOpen /><h2>Связанных объектов нет</h2><p>Пустое состояние демонстрирует будущий раздел связей.</p></section>}
    {tab === 'technical' && <section className="card"><h2>Технические mock-данные</h2><div className="toolbar"><input className="input" placeholder="Поиск в технических данных" /><button className="button button-secondary" onClick={() => mockAction('Технические данные скопированы')}><Copy />Копировать</button></div><pre className="code-block">ruleId: FS-DEMO-001{`\n`}engine: mock{`\n`}confidenceType: heuristic{`\n`}networkAccess: false{`\n`}isDemo: true</pre></section>}
  </>;
}

function QuarantinePage({ items, restore, remove }: { items: string[]; restore: (name: string) => void; remove: (name: string) => void }) {
  return <><PageHeader title="Карантин" text="Экран работает только с локальным mock-состоянием. Реальные файлы не изменяются." /><div className="info-banner warning"><Info /><div><strong>Демо-режим</strong><span>В этой версии карантин не перемещает и не шифрует файлы.</span></div></div>
    {items.length === 0 ? <section className="empty card"><Archive size={44} /><h2>Карантин пуст</h2><p>Добавьте демонстрационный объект со страницы результата.</p></section> : <div className="quarantine-list">{items.map((name) => <section className="card selected-object" key={name}><Archive /><div><strong>{name}</strong><span>Помещён в mock-карантин · исходное расположение: C:\Demo</span></div><DemoBadge /><button className="button button-secondary" onClick={() => restore(name)}>Восстановить</button><button className="icon-button danger" onClick={() => remove(name)} aria-label="Удалить навсегда"><Trash2 /></button></section>)}</div>}</>;
}

type SettingsSection = 'general' | 'appearance' | 'window' | 'scan' | 'privacy' | 'exclusions' | 'developer' | 'updates' | 'subscription' | 'about';

function SettingsPage({
  theme, closeBehavior, developerMode, crashReportsEnabled, automaticUpdates, exclusions,
  setTheme, setCloseBehavior, requestDeveloperMode, setCrashReportsEnabled, setAutomaticUpdates,
  addExclusion, removeExclusion, checkUpdates, navigate, restartOnboarding, requestReset,
}: {
  theme: ThemePreference; closeBehavior: CloseBehavior; developerMode: boolean; crashReportsEnabled: boolean; automaticUpdates: boolean; exclusions: string[];
  setTheme: (theme: ThemePreference) => void; setCloseBehavior: (behavior: CloseBehavior) => void; requestDeveloperMode: () => void;
  setCrashReportsEnabled: (value: boolean) => void; setAutomaticUpdates: (value: boolean) => void; addExclusion: () => void; removeExclusion: (path: string) => void;
  checkUpdates: () => void; navigate: (page: Page) => void; restartOnboarding: () => void; requestReset: () => void;
}) {
  const [section, setSection] = useState<SettingsSection>('general');
  const navigation: [SettingsSection, string][] = [['general', 'Общие'], ['appearance', 'Внешний вид'], ['window', 'Поведение окна'], ['scan', 'Проверка'], ['privacy', 'Приватность'], ['exclusions', 'Исключения'], ['developer', 'Режим разработчика'], ['updates', 'Обновления'], ['subscription', 'Подписка'], ['about', 'О программе']];
  return <><PageHeader title="Настройки" text="Настройки хранятся локально и не синхронизируются с сервером." />
    <section className="settings-layout"><nav className="settings-nav" aria-label="Разделы настроек">{navigation.map(([id, label]) => <button className={section === id ? 'active' : ''} onClick={() => setSection(id)} key={id}>{label}</button>)}</nav>
    <div className="settings-content">
      {section === 'general' && <section className="card"><h2>Общие</h2><div className="setting-row"><div><strong>Язык интерфейса</strong><span>Архитектура локализации подготовлена; в версии 0.1.0 доступен русский язык.</span></div><select className="input compact" disabled><option>Русский</option></select></div><div className="setting-row"><div><strong>Повторить onboarding</strong><span>Снова показать сценарий первого запуска.</span></div><button className="button button-secondary" onClick={restartOnboarding}>Открыть</button></div><div className="setting-row"><div><strong>Сбросить настройки</strong><span>Удалить локальные настройки и mock-состояние.</span></div><button className="button button-danger" onClick={requestReset}><RotateCcw />Сбросить</button></div></section>}
      {section === 'appearance' && <section className="card"><h2>Внешний вид</h2><div className="setting-row"><div><strong>Тема интерфейса</strong><span>Можно использовать системную, светлую или тёмную тему.</span></div><select className="input compact" value={theme} onChange={(event) => setTheme(event.target.value as ThemePreference)}><option value="system">Системная</option><option value="dark">Тёмная</option><option value="light">Светлая</option></select></div><div className="setting-row disabled-row"><div><strong>Акцентный цвет</strong><span>Фирменный синий зафиксирован в первой версии.</span></div><span className="badge neutral">Скоро</span></div></section>}
      {section === 'window' && <section className="card"><h2>Поведение окна</h2><div className="setting-row"><div><strong>При закрытии окна</strong><span>Настройка применяется к нативному окну Tauri.</span></div><select className="input compact" value={closeBehavior} onChange={(event) => setCloseBehavior(event.target.value as CloseBehavior)}><option value="tray">Сворачивать в трей</option><option value="quit">Закрывать полностью</option></select></div></section>}
      {section === 'scan' && <section className="card"><h2>Проверка</h2><div className="setting-row"><div><strong>Локальная проверка</strong><span>Внешняя отправка файлов запрещена. Аналитический модуль появится позже.</span></div><span className="badge neutral">Скоро</span></div><div className="setting-row"><div><strong>Активный URL-анализ</strong><span>Всегда запускается вручную.</span></div><span className="badge neutral">Скоро</span></div></section>}
      {section === 'privacy' && <section className="card"><h2>Приватность</h2><div className="setting-row"><div><strong>Обезличенные отчёты о сбоях</strong><span>Выключены по умолчанию. В версии 0.1.0 отправка фактически не выполняется.</span></div><button className={`switch ${crashReportsEnabled ? 'on' : ''}`} role="switch" aria-checked={crashReportsEnabled} onClick={() => setCrashReportsEnabled(!crashReportsEnabled)}><span /></button></div><div className="status-banner success"><ShieldCheck /><span>Телеметрия и внешние API отсутствуют.</span></div></section>}
      {section === 'exclusions' && <section className="card"><div className="card-title-row"><div><h2>Исключения</h2><p>Список хранится локально. Исключения не выполняют реальное действие в версии 0.1.0.</p></div><button className="button button-primary" onClick={addExclusion}><Plus />Добавить путь</button></div>{exclusions.length === 0 ? <div className="empty compact-empty"><CircleHelp /><strong>Исключений пока нет</strong></div> : exclusions.map((path) => <div className="table-row" key={path}><span className="mono-value">{path}</span><button className="icon-button danger" onClick={() => removeExclusion(path)} aria-label="Удалить исключение"><Trash2 /></button></div>)}</section>}
      {section === 'developer' && <section className="card"><h2>Режим разработчика</h2><div className="setting-row"><div><strong>Технические данные</strong><span>Отображает хеши, идентификаторы правил и mock-события.</span></div><button className={`switch ${developerMode ? 'on' : ''}`} role="switch" aria-checked={developerMode} onClick={requestDeveloperMode}><span /></button></div>{developerMode && <pre className="code-block">developerMode: true{`\n`}rawEvents: mock-only{`\n`}networkAccess: false</pre>}</section>}
      {section === 'updates' && <section className="card"><h2>Обновления</h2><div className="setting-row"><div><strong>Текущая версия</strong><span>0.1.0 · канал stable</span></div><button className="button button-secondary" onClick={checkUpdates}>Проверить обновления</button></div><div className="setting-row"><div><strong>Автоматическая проверка</strong><span>Используется mock-сервис без подключения к production-серверу.</span></div><button className={`switch ${automaticUpdates ? 'on' : ''}`} role="switch" aria-checked={automaticUpdates} onClick={() => setAutomaticUpdates(!automaticUpdates)}><span /></button></div></section>}
      {section === 'subscription' && <section className="card"><h2>Подписка</h2><p>Текущий тариф — FileScope Free.</p><button className="button button-primary" onClick={() => navigate('subscription')}><Crown />Открыть тарифы</button></section>}
      {section === 'about' && <section className="card"><h2>О программе</h2><p>FileScope 0.1.0 — первая демонстрационная UI-версия.</p><button className="button button-secondary" onClick={() => navigate('about')}>Подробнее</button></section>}
    </div></section></>;
}

export function App() {
  const { preferences, patchPreferences, resetPreferences } = useAppPreferences();
  const initialPage = isPage(preferences.lastPage) ? preferences.lastPage : 'home';
  const [page, setPage] = useState<Page>(initialPage);
  const [dialog, setDialog] = useState<DialogKind>(null);
  const [selectedReport, setSelectedReport] = useState<DemoReport>(demoReports[3]);
  const [quarantine, setQuarantine] = useState<string[]>([]);
  const [selectedObject, setSelectedObject] = useState<SelectedObject | null>(null);
  const [toasts, setToasts] = useState<ToastMessage[]>([]);
  const [systemDark, setSystemDark] = useState(() => window.matchMedia?.('(prefers-color-scheme: dark)').matches ?? true);
  const [showOnboarding, setShowOnboarding] = useState(!preferences.onboardingCompleted);

  const resolvedTheme = preferences.theme === 'system' ? (systemDark ? 'dark' : 'light') : preferences.theme;
  const activeTitle = useMemo(() => pages.find(([id]) => id === page)?.[1] ?? ({ result: 'Результат', subscription: 'Подписка', about: 'О программе' } as const)[page as 'result' | 'subscription' | 'about'] ?? 'FileScope', [page]);

  const navigate = useCallback((nextPage: Page) => {
    setPage(nextPage);
    patchPreferences({ lastPage: nextPage });
  }, [patchPreferences]);

  const pushToast = useCallback((title: string, tone: ToastTone = 'info', text?: string) => {
    const id = `${Date.now()}-${Math.random()}`;
    setToasts((current) => [...current, { id, title, tone, text }]);
    window.setTimeout(() => setToasts((current) => current.filter((item) => item.id !== id)), 4200);
  }, []);

  const selectObject = useCallback(async () => {
    const selected = await selectLocalObject(false);
    if (!selected) {
      setDialog('unavailable');
      return;
    }
    setSelectedObject(selected);
    navigate('files');
    pushToast('Объект выбран', 'info', 'Анализ не запускался. Путь хранится только до завершения сессии.');
  }, [navigate, pushToast]);

  useEffect(() => {
    const media = window.matchMedia?.('(prefers-color-scheme: dark)');
    if (!media) return;
    const listener = (event: MediaQueryListEvent) => setSystemDark(event.matches);
    media.addEventListener('change', listener);
    return () => media.removeEventListener('change', listener);
  }, []);

  useEffect(() => {
    let unlisten: (() => void) | null = null;
    void bindCloseBehavior(() => preferences.closeBehavior).then((value) => { unlisten = value; });
    return () => unlisten?.();
  }, [preferences.closeBehavior]);

  useEffect(() => {
    let listeners: (() => void)[] = [];
    void bindNativeNavigation((target) => { if (isPage(target)) navigate(target); }, () => { void selectObject(); }).then((result) => { listeners = result; });
    return () => listeners.forEach((unlisten) => unlisten());
  }, [navigate, selectObject]);

  const openReport = (report: DemoReport) => { setSelectedReport(report); navigate('result'); };
  const addQuarantine = () => {
    setQuarantine((current) => current.includes(selectedReport.name) ? current : [...current, selectedReport.name]);
    navigate('quarantine');
    pushToast('Объект помещён в mock-карантин', 'success');
  };
  const removeQuarantine = (name: string) => {
    setQuarantine((current) => current.filter((item) => item !== name));
    pushToast('Демонстрационная запись удалена', 'success');
  };
  const restoreQuarantine = (name: string) => {
    setQuarantine((current) => current.filter((item) => item !== name));
    pushToast('Демонстрационная запись восстановлена', 'success');
  };
  const addCurrentExclusion = () => {
    const path = selectedObject?.path ?? `C:\Demo\${selectedReport.name}`;
    if (!preferences.exclusions.includes(path)) patchPreferences({ exclusions: [...preferences.exclusions, path] });
    pushToast('Объект добавлен в исключения', 'success');
  };
  const chooseExclusion = async () => {
    const selected = await selectLocalObject(false);
    if (!selected) { setDialog('unavailable'); return; }
    if (!preferences.exclusions.includes(selected.path)) patchPreferences({ exclusions: [...preferences.exclusions, selected.path] });
    pushToast('Путь добавлен в исключения', 'success');
  };
  const requestDeveloperMode = () => {
    if (preferences.developerMode) {
      patchPreferences({ developerMode: false });
      pushToast('Режим разработчика выключен', 'info');
    } else setDialog('developer');
  };
  const confirmDialog = () => {
    if (dialog === 'developer') {
      patchPreferences({ developerMode: true });
      pushToast('Режим разработчика включён', 'warning');
    } else if (dialog === 'reset') {
      resetPreferences();
      setQuarantine([]);
      setSelectedObject(null);
      setShowOnboarding(true);
      navigate('home');
      pushToast('Настройки сброшены', 'success');
    }
    setDialog(null);
  };

  let content = <HomePage navigate={navigate} selectObject={selectObject} />;
  if (page === 'scan') content = <ScanPage selectObject={selectObject} unavailable={() => setDialog('unavailable')} />;
  if (page === 'links') content = <LinksPage unavailable={() => setDialog('unavailable')} showActiveWarning={() => setDialog('active-url')} />;
  if (page === 'files') content = <FilesPage navigate={navigate} selectObject={selectObject} selected={selectedObject} />;
  if (page === 'archives') content = <ArchivesPage selectObject={selectObject} unavailable={() => setDialog('unavailable')} />;
  if (page === 'programs') content = <ProgramsPage unavailable={() => setDialog('unavailable')} />;
  if (page === 'reports') content = <ReportsPage openReport={openReport} />;
  if (page === 'result') content = <ResultPage report={selectedReport} developerMode={preferences.developerMode} quarantine={addQuarantine} mockAction={(title) => pushToast(title, 'success', 'Изменено только локальное mock-состояние.')} addExclusion={addCurrentExclusion} />;
  if (page === 'quarantine') content = <QuarantinePage items={quarantine} restore={restoreQuarantine} remove={removeQuarantine} />;
  if (page === 'settings') content = <SettingsPage theme={preferences.theme} closeBehavior={preferences.closeBehavior} developerMode={preferences.developerMode} crashReportsEnabled={preferences.crashReportsEnabled} automaticUpdates={preferences.automaticUpdates} exclusions={preferences.exclusions} setTheme={(theme) => patchPreferences({ theme })} setCloseBehavior={(closeBehavior) => patchPreferences({ closeBehavior })} requestDeveloperMode={requestDeveloperMode} setCrashReportsEnabled={(crashReportsEnabled) => patchPreferences({ crashReportsEnabled })} setAutomaticUpdates={(automaticUpdates) => patchPreferences({ automaticUpdates })} addExclusion={() => { void chooseExclusion(); }} removeExclusion={(path) => patchPreferences({ exclusions: preferences.exclusions.filter((item) => item !== path) })} checkUpdates={() => pushToast('Установлена актуальная версия', 'success', 'Mock-проверка: FileScope 0.1.0')} navigate={navigate} restartOnboarding={() => setShowOnboarding(true)} requestReset={() => setDialog('reset')} />;
  if (page === 'subscription') content = <SubscriptionPage onUnavailable={() => setDialog('unavailable')} />;
  if (page === 'about') content = <AboutPage onShowTerms={() => setDialog('terms')} />;

  return <div className={`app theme-${resolvedTheme}`}>
    <aside className={`sidebar ${preferences.sidebarCollapsed ? 'collapsed' : ''}`} aria-label="Основная навигация">
      <button className="brand" onClick={() => navigate('home')}><span className="brand-mark"><ShieldCheck /></span><strong>FileScope</strong></button>
      <nav>{pages.map(([id, label, Icon]) => <button key={id} title={label} className={`nav-item ${page === id ? 'active' : ''}`} onClick={() => navigate(id)}><Icon /><span>{label}</span></button>)}</nav>
      <div className="sidebar-bottom"><button className="subscription-card" onClick={() => navigate('subscription')}><strong>FileScope Free</strong><span>Перейти на Pro</span></button><button className="nav-item utility-item" onClick={() => navigate('about')} title="О программе"><CircleHelp /><span>О программе</span></button><small>Версия 0.1.0</small></div>
    </aside>
    <main className="main"><header className="titlebar"><button className="icon-button" onClick={() => patchPreferences({ sidebarCollapsed: !preferences.sidebarCollapsed })} aria-label="Свернуть боковую панель"><Menu /></button>{(page === 'result' || page === 'subscription' || page === 'about') && <button className="icon-button" onClick={() => navigate(page === 'result' ? 'reports' : 'settings')} aria-label="Назад"><ChevronLeft /></button>}<strong>{activeTitle}</strong><span className="title-spacer" /><span className="offline-status"><CheckCircle2 />Локальный режим</span></header><div className="content">{content}</div></main>
    {dialog && <Dialog kind={dialog} onClose={() => setDialog(null)} onConfirm={confirmDialog} />}
    <ToastHost messages={toasts} onDismiss={(id) => setToasts((current) => current.filter((item) => item.id !== id))} />
    {showOnboarding && <Onboarding closeBehavior={preferences.closeBehavior} onComplete={(closeBehavior) => { patchPreferences({ onboardingCompleted: true, closeBehavior }); setShowOnboarding(false); pushToast('FileScope готов к работе', 'success'); }} />}
  </div>;
}
