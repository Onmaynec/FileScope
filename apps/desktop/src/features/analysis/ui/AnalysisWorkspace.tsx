import { useEffect, useMemo, useRef, useState } from 'react';
import {
  AlertTriangle, Archive, CheckCircle2, Clock3, FileSearch, Globe2, ListChecks,
  LoaderCircle, Play, Plus, RefreshCcw, Square, Trash2, Upload, XCircle,
} from 'lucide-react';
import { selectLocalObjects } from '../../../shared/native/native-bridge';
import { analyzeArchive, analyzeFile, analyzeUrlActive, analyzeUrlPassive } from '../api/analysis-api';
import { saveReport } from '../model/analysis-storage';
import {
  appendUniqueQueueItems,
  cancelOpenQueueItems,
  createQueueItem,
  pendingQueueItems,
  removeFinishedQueueItems,
  updateQueueItem,
  type AnalysisQueueItem,
  type QueueStatus,
} from '../model/scan-queue';
import type { AnalysisLimits, AnalysisReport, ObjectKind } from '../model/types';
import { ReportView } from './ReportView';

interface AnalysisWorkspaceProps {
  initialMode?: ObjectKind;
  initialPath?: string;
  limits: AnalysisLimits;
  onReport?: (report: AnalysisReport) => void;
}

const statusLabels: Record<QueueStatus, string> = {
  pending: 'Ожидает',
  running: 'Выполняется',
  completed: 'Готово',
  failed: 'Ошибка',
  cancelled: 'Отменено',
};

export function AnalysisWorkspace({ initialMode = 'file', initialPath = '', limits, onReport }: AnalysisWorkspaceProps) {
  const [mode, setMode] = useState<ObjectKind>(initialMode);
  const [path, setPath] = useState(initialPath);
  const [url, setUrl] = useState('https://example.com/download?source=filescope');
  const [activeNetwork, setActiveNetwork] = useState(false);
  const [networkConsent, setNetworkConsent] = useState(false);
  const [queue, setQueue] = useState<AnalysisQueueItem[]>([]);
  const [report, setReport] = useState<AnalysisReport | null>(null);
  const [error, setError] = useState('');
  const [running, setRunning] = useState(false);
  const [activeId, setActiveId] = useState<string | null>(null);
  const runToken = useRef(0);

  useEffect(() => setMode(initialMode), [initialMode]);
  useEffect(() => {
    if (!initialPath) return;
    setPath(initialPath);
    const displayName = initialPath.split(/[\\/]/).filter(Boolean).at(-1) ?? initialPath;
    setQueue((current) => appendUniqueQueueItems(current, [createQueueItem('file', initialPath, displayName)]));
  }, [initialPath]);

  const pendingCount = queue.filter((item) => item.status === 'pending').length;
  const finishedCount = queue.filter((item) => ['completed', 'failed', 'cancelled'].includes(item.status)).length;
  const queueProgress = queue.length ? Math.round((finishedCount / queue.length) * 100) : 0;
  const currentInputValid = mode === 'url'
    ? Boolean(url.trim()) && (!activeNetwork || networkConsent)
    : Boolean(path.trim());
  const canStart = !running && (pendingCount > 0 || currentInputValid);
  const selectedLabel = useMemo(() => path.split(/[\\/]/).filter(Boolean).at(-1) ?? path, [path]);
  const activeItem = queue.find((item) => item.id === activeId);

  const chooseObjects = async () => {
    setError('');
    const selected = await selectLocalObjects({ multiple: true, directory: false });
    if (!selected.length) return;
    setPath(selected[0].path);
    setReport(null);
    const items = selected.map((item) => createQueueItem(mode === 'archive' ? 'archive' : 'file', item.path, item.displayName));
    setQueue((current) => appendUniqueQueueItems(current, items));
  };

  const enqueueUrl = () => {
    if (!url.trim() || (activeNetwork && !networkConsent)) return;
    const item = createQueueItem('url', url.trim(), urlDisplayName(url), activeNetwork);
    setQueue((current) => appendUniqueQueueItems(current, [item]));
    setReport(null);
    setError('');
  };

  const currentItem = (): AnalysisQueueItem | null => {
    if (mode === 'url') {
      if (!url.trim() || (activeNetwork && !networkConsent)) return null;
      return createQueueItem('url', url.trim(), urlDisplayName(url), activeNetwork);
    }
    if (!path.trim()) return null;
    return createQueueItem(mode, path, selectedLabel);
  };

  const runItem = async (item: AnalysisQueueItem): Promise<AnalysisReport> => {
    if (item.kind === 'file') return analyzeFile(item.target, limits);
    if (item.kind === 'archive') return analyzeArchive(item.target, limits);
    return item.activeNetwork
      ? analyzeUrlActive(item.target, limits)
      : analyzeUrlPassive(item.target);
  };

  const start = async () => {
    if (!canStart) return;
    let preparedQueue = queue;
    if (!pendingQueueItems(preparedQueue).length) {
      const item = currentItem();
      if (!item) return;
      preparedQueue = appendUniqueQueueItems(preparedQueue, [item]);
      setQueue(preparedQueue);
    }

    const items = pendingQueueItems(preparedQueue);
    if (!items.length) return;
    const token = ++runToken.current;
    setRunning(true);
    setError('');
    setReport(null);

    for (const item of items) {
      if (runToken.current !== token) break;
      const startedAt = new Date().toISOString();
      setActiveId(item.id);
      setQueue((current) => updateQueueItem(current, item.id, {
        status: 'running',
        startedAt,
        completedAt: undefined,
        error: undefined,
        report: undefined,
      }));

      try {
        const result = await runItem(item);
        if (runToken.current !== token) break;
        saveReport(result);
        setQueue((current) => updateQueueItem(current, item.id, {
          status: 'completed',
          completedAt: new Date().toISOString(),
          report: result,
        }));
        setReport(result);
        onReport?.(result);
      } catch (reason) {
        if (runToken.current !== token) break;
        const message = reason instanceof Error ? reason.message : String(reason);
        setQueue((current) => updateQueueItem(current, item.id, {
          status: 'failed',
          completedAt: new Date().toISOString(),
          error: message,
        }));
        setError(message);
      }
    }

    if (runToken.current === token) {
      setRunning(false);
      setActiveId(null);
    }
  };

  const cancel = () => {
    runToken.current += 1;
    setQueue((current) => cancelOpenQueueItems(current));
    setRunning(false);
    setActiveId(null);
    setError('');
  };

  const resetView = () => {
    setReport(null);
    setError('');
  };

  const removeItem = (id: string) => {
    if (id === activeId) return;
    setQueue((current) => current.filter((item) => item.id !== id));
  };

  const retryItem = (id: string) => {
    setQueue((current) => updateQueueItem(current, id, {
      status: 'pending',
      startedAt: undefined,
      completedAt: undefined,
      report: undefined,
      error: undefined,
    }));
  };

  return <div className="analysis-workspace">
    <div className="analysis-mode-tabs" role="tablist" aria-label="Тип анализа">
      <button role="tab" aria-selected={mode === 'file'} className={mode === 'file' ? 'active' : ''} onClick={() => { setMode('file'); resetView(); }}><FileSearch />Файл</button>
      <button role="tab" aria-selected={mode === 'url'} className={mode === 'url' ? 'active' : ''} onClick={() => { setMode('url'); resetView(); }}><Globe2 />URL</button>
      <button role="tab" aria-selected={mode === 'archive'} className={mode === 'archive' ? 'active' : ''} onClick={() => { setMode('archive'); resetView(); }}><Archive />ZIP-архив</button>
    </div>

    <section className="card analysis-input-card">
      <div className="card-title-row"><div><span className="analysis-kicker">FileScope Core 0.2</span><h2>{mode === 'file' ? 'Локальный статический анализ файлов' : mode === 'archive' ? 'Безопасный просмотр ZIP-архивов' : 'Анализ URL'}</h2><p>{mode === 'url' ? 'Сначала выполняется пассивный разбор. Активная сеть включается только вручную.' : 'Можно добавить несколько объектов: очередь обрабатывается последовательно, без запуска и внешней отправки.'}</p></div><span className="badge neutral">Реальные данные</span></div>

      {mode === 'url' ? <>
        <label className="field-label" htmlFor="analysis-url">Адрес</label>
        <input id="analysis-url" className="input" value={url} onChange={(event) => { setUrl(event.target.value.trimStart()); setReport(null); setError(''); }} placeholder="https://example.com/path" spellCheck={false} />
        <div className="analysis-network-choice">
          <button type="button" className={`choice-card ${!activeNetwork ? 'selected' : ''}`} onClick={() => { setActiveNetwork(false); setNetworkConsent(false); }}><span><strong>Пассивный анализ</strong><small>Без DNS, HTTP и открытия страницы.</small></span></button>
          <button type="button" className={`choice-card ${activeNetwork ? 'selected' : ''}`} onClick={() => setActiveNetwork(true)}><span><strong>Ручная активная проверка</strong><small>DNS и минимальный HEAD/Range-запрос без загрузки страницы целиком.</small></span></button>
        </div>
        {activeNetwork && <label className="consent-row analysis-consent"><input type="checkbox" checked={networkConsent} onChange={(event) => setNetworkConsent(event.target.checked)} /><span>Я понимаю, что сервер увидит IP-адрес устройства, и запускаю сетевую проверку вручную.</span></label>}
        <button className="button button-secondary analysis-enqueue" disabled={!currentInputValid || running} onClick={enqueueUrl}><Plus />Добавить URL в очередь</button>
      </> : <>
        <button className="dropzone analysis-dropzone" onClick={() => void chooseObjects()}>
          <Upload size={42} />
          <strong>{path ? selectedLabel : mode === 'archive' ? 'Выберите один или несколько ZIP-архивов' : 'Выберите один или несколько файлов'}</strong>
          <span>{path || (mode === 'archive' ? 'Архивы читаются без извлечения содержимого на диск.' : 'Поддерживаются обычные файлы; PE-файлы получают дополнительный разбор.')}</span>
          <span className="button button-primary">{path ? 'Добавить другие объекты' : 'Открыть файловый диалог'}</span>
        </button>
      </>}

      <div className="analysis-controls">
        {!running ? <button className="button button-primary analysis-start" disabled={!canStart} onClick={() => void start()}><Play />{pendingCount > 0 ? `Запустить очередь (${pendingCount})` : mode === 'url' && activeNetwork ? 'Запустить активную проверку' : 'Начать анализ'}</button> : <button className="button button-danger" onClick={cancel}><Square />Отменить очередь</button>}
        {(report || error) && !running && <button className="button button-secondary" onClick={resetView}><RefreshCcw />Скрыть результат</button>}
        <span className="helper-text">Лимит файла: {Math.round(limits.maximumFileSizeBytes / 1024 / 1024)} МБ</span>
      </div>
    </section>

    {queue.length > 0 && <section className="card analysis-queue" aria-live="polite">
      <div className="card-title-row"><div><h2><ListChecks />Очередь проверок</h2><p>{running && activeItem ? `Сейчас: ${activeItem.displayName}` : pendingCount ? `Ожидает запуска: ${pendingCount}` : 'Все задания обработаны.'}</p></div><div className="analysis-queue__toolbar"><strong>{finishedCount}/{queue.length}</strong><button className="button button-secondary" disabled={running || finishedCount === 0} onClick={() => setQueue((current) => removeFinishedQueueItems(current))}><Trash2 />Очистить завершённые</button></div></div>
      <div className="analysis-progress__track analysis-queue__progress"><span style={{ width: `${queueProgress}%` }} /></div>
      <div className="analysis-queue__list">{queue.map((item) => <QueueRow key={item.id} item={item} active={item.id === activeId} onRemove={() => removeItem(item.id)} onRetry={() => retryItem(item.id)} onOpenReport={() => item.report && setReport(item.report)} />)}</div>
      {running && <p className="helper-text analysis-queue__notice">Точный процент текущего анализатора не подменяется декоративным значением. Общий прогресс отражает только реально завершённые задания. При отмене ожидающие задания останавливаются сразу, а поздний результат уже запущенной системной операции игнорируется.</p>}
    </section>}

    {running && activeItem && <section className="card analysis-progress">
      <div className="analysis-progress__top"><span className="analysis-progress__icon"><LoaderCircle /></span><div><strong>Анализируется: {activeItem.displayName}</strong><span>{activeItem.kind === 'url' && activeItem.activeNetwork ? 'Выполняется разрешённая пользователем минимальная сетевая проверка.' : 'Объект не запускается. Выполняется локальный статический разбор.'}</span></div><b>{finishedCount}/{queue.length}</b></div>
    </section>}

    {error && <section className="status-banner warning analysis-error" role="alert"><AlertTriangle /><div><strong>Одно из заданий завершилось ошибкой</strong><span>{error}</span></div></section>}
    {report && <ReportView report={report} />}
  </div>;
}

function QueueRow({ item, active, onRemove, onRetry, onOpenReport }: { item: AnalysisQueueItem; active: boolean; onRemove: () => void; onRetry: () => void; onOpenReport: () => void }) {
  const StatusIcon = item.status === 'completed' ? CheckCircle2 : item.status === 'failed' ? XCircle : item.status === 'running' ? LoaderCircle : item.status === 'cancelled' ? Square : Clock3;
  return <article className={`analysis-queue-item status-${item.status} ${active ? 'active' : ''}`}>
    <span className="analysis-queue-item__status"><StatusIcon /></span>
    <button className="analysis-queue-item__body" disabled={!item.report} onClick={onOpenReport}><strong>{item.displayName}</strong><span>{objectLabel(item.kind)}{item.kind === 'url' ? ` · ${item.activeNetwork ? 'активная' : 'пассивная'}` : ''} · {statusLabels[item.status]}</span>{item.error && <small>{item.error}</small>}</button>
    {(item.status === 'failed' || item.status === 'cancelled') && <button className="icon-button" title="Повторить" onClick={onRetry}><RefreshCcw /></button>}
    {item.status !== 'running' && <button className="icon-button danger" title="Убрать из очереди" onClick={onRemove}><Trash2 /></button>}
  </article>;
}

function objectLabel(kind: ObjectKind): string {
  return kind === 'file' ? 'Файл' : kind === 'archive' ? 'ZIP-архив' : 'URL';
}

function urlDisplayName(value: string): string {
  try {
    return new URL(value.trim()).hostname || value.trim();
  } catch {
    return value.trim();
  }
}
