import { getCurrentWebview } from '@tauri-apps/api/webview';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  AlertTriangle, Archive, CheckCircle2, ChevronLeft, ChevronRight, Clock3, FileSearch,
  Globe2, ListChecks, LoaderCircle, Play, Plus, RefreshCcw, Search, Square, Trash2,
  Upload, XCircle,
} from 'lucide-react';
import { APP_VERSION } from '../../../shared/config/app-version';
import { selectLocalObjects } from '../../../shared/native/native-bridge';
import { Select } from '../../../shared/ui/Select';
import {
  AnalysisError,
  analyzeArchive,
  analyzeFile,
  analyzeUrlActive,
  analyzeUrlPassive,
  cancelAnalysis,
  friendlyAnalysisError,
} from '../api/analysis-api';
import { inspectLocalPaths } from '../api/local-path-api';
import { saveReport } from '../model/analysis-storage';
import {
  appendUniqueQueueItemsDetailed,
  confirmQueueCancellation,
  createQueueItem,
  isFinishedStatus,
  pendingQueueItems,
  removeFinishedQueueItems,
  requestCurrentCancellation,
  requestQueueCancellation,
  updateQueueItem,
  type AnalysisQueueItem,
  type QueueStatus,
} from '../model/scan-queue';
import type { AnalysisLimits, AnalysisReport, ObjectKind, RiskLevel } from '../model/types';
import { ReportView } from './ReportView';

interface AnalysisWorkspaceProps {
  initialMode?: ObjectKind;
  initialPath?: string;
  limits: AnalysisLimits;
  onReport?: (report: AnalysisReport) => void;
}

type DropState = 'idle' | 'over' | 'adding' | 'success' | 'rejected';
type StatusFilter = 'all' | 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';
type RiskFilter = 'all' | RiskLevel;
type MobilePane = 'queue' | 'details';

const statusLabels: Record<QueueStatus, string> = {
  pending: 'Ожидает',
  running: 'Выполняется',
  cancelling: 'Останавливается',
  completed: 'Готово',
  failed: 'Ошибка',
  cancelled: 'Отменено',
};
const statusOptions = [
  { value: 'all', label: 'Все статусы' },
  { value: 'pending', label: 'Ожидают' },
  { value: 'running', label: 'Выполняются' },
  { value: 'completed', label: 'Готовы' },
  { value: 'failed', label: 'Ошибки' },
  { value: 'cancelled', label: 'Отменены' },
] as const;
const riskOptions = [
  { value: 'all', label: 'Любой риск' },
  { value: 'noThreatsFound', label: 'Без признаков' },
  { value: 'caution', label: 'Внимание' },
  { value: 'highRisk', label: 'Высокий риск' },
  { value: 'dangerous', label: 'Опасный' },
] as const;

export function AnalysisWorkspace({ initialMode = 'file', initialPath = '', limits, onReport }: AnalysisWorkspaceProps) {
  const [mode, setMode] = useState<ObjectKind>(initialMode);
  const [path, setPath] = useState(initialPath);
  const [url, setUrl] = useState('https://example.com/download?source=filescope');
  const [activeNetwork, setActiveNetwork] = useState(false);
  const [networkConsent, setNetworkConsent] = useState(false);
  const [queue, setQueue] = useState<AnalysisQueueItem[]>([]);
  const [reports, setReports] = useState<Record<string, AnalysisReport>>({});
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [error, setError] = useState('');
  const [queueNotice, setQueueNotice] = useState('');
  const [running, setRunning] = useState(false);
  const [activeId, setActiveId] = useState<string | null>(null);
  const [query, setQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('all');
  const [riskFilter, setRiskFilter] = useState<RiskFilter>('all');
  const [dropState, setDropState] = useState<DropState>('idle');
  const [dropMessage, setDropMessage] = useState('Перетащите файлы сюда или загрузите их вручную.');
  const [mobilePane, setMobilePane] = useState<MobilePane>('queue');
  const dropzoneRef = useRef<HTMLButtonElement>(null);
  const stopRequestedRef = useRef(false);
  const detailScrollRef = useRef<HTMLDivElement>(null);
  const manualSelectionRef = useRef(false);
  const queueRef = useRef<AnalysisQueueItem[]>([]);

  useEffect(() => setMode(initialMode), [initialMode]);
  useEffect(() => { queueRef.current = queue; }, [queue]);
  useEffect(() => {
    if (!initialPath) return;
    setPath(initialPath);
    const displayName = fileName(initialPath);
    const item = createQueueItem('file', initialPath, displayName);
    const appended = appendUniqueQueueItemsDetailed(queueRef.current, [item]);
    queueRef.current = appended.queue;
    setQueue(appended.queue);
    const actual = appended.added[0] ?? appended.duplicates[0]?.existing;
    setSelectedId((current) => current ?? actual?.id ?? null);
  }, [initialPath]);

  const pendingCount = queue.filter((item) => item.status === 'pending').length;
  const finishedCount = queue.filter((item) => isFinishedStatus(item.status)).length;
  const queueProgress = queue.length ? Math.round((finishedCount / queue.length) * 100) : 0;
  const currentInputValid = mode === 'url'
    ? Boolean(url.trim()) && (!activeNetwork || networkConsent)
    : Boolean(path.trim());
  const canStart = !running && (pendingCount > 0 || currentInputValid);
  const selectedLabel = useMemo(() => fileName(path), [path]);
  const activeItem = queue.find((item) => item.id === activeId);
  const selectedItem = queue.find((item) => item.id === selectedId) ?? null;
  const selectedReport = selectedItem?.reportId ? reports[selectedItem.reportId] : undefined;

  useEffect(() => {
    if (selectedId && !queue.some((item) => item.id === selectedId)) {
      manualSelectionRef.current = false;
      setSelectedId(null);
    }
  }, [queue, selectedId]);

  useEffect(() => {
    if (detailScrollRef.current) detailScrollRef.current.scrollTop = 0;
  }, [selectedId]);

  const filteredQueue = useMemo(() => {
    const normalizedQuery = query.trim().toLocaleLowerCase('ru-RU');
    return queue.filter((item) => {
      if (normalizedQuery && !`${item.displayName} ${item.target}`.toLocaleLowerCase('ru-RU').includes(normalizedQuery)) return false;
      if (statusFilter !== 'all') {
        const normalizedStatus = item.status === 'cancelling' ? 'running' : item.status;
        if (normalizedStatus !== statusFilter) return false;
      }
      if (riskFilter !== 'all' && item.riskLevel !== riskFilter) return false;
      return true;
    });
  }, [query, queue, riskFilter, statusFilter]);

  const completedItems = useMemo(
    () => queue.filter((item) => item.status === 'completed' && item.reportId && reports[item.reportId]),
    [queue, reports],
  );
  const selectedCompletedIndex = completedItems.findIndex((item) => item.id === selectedId);

  const showQueueNotice = useCallback((message: string) => {
    setQueueNotice(message);
    window.setTimeout(() => setQueueNotice(''), 2400);
  }, []);

  const addCandidates = useCallback((paths: string[], source: 'dialog' | 'drop') => {
    if (!paths.length) return;
    void (async () => {
      setDropState(source === 'drop' ? 'adding' : 'idle');
      const candidates = await inspectLocalPaths(paths, mode === 'archive');
      const accepted = candidates.filter((item) => item.accepted);
      const rejected = candidates.filter((item) => !item.accepted);
      let addedCount = 0;
      let duplicateCount = 0;
      if (accepted.length) {
        const items = accepted.map((item) => createQueueItem(mode === 'archive' ? 'archive' : 'file', item.path, item.displayName));
        const appended = appendUniqueQueueItemsDetailed(queueRef.current, items);
        queueRef.current = appended.queue;
        setQueue(appended.queue);
        addedCount = appended.added.length;
        duplicateCount = appended.duplicates.length;
        const actual = appended.added[0] ?? appended.duplicates[0]?.existing;
        setSelectedId((current) => current ?? actual?.id ?? null);
        setPath(accepted[0]?.path ?? '');
      }
      const firstReason = rejected[0]?.reason;
      if (rejected.length || duplicateCount) {
        setDropState(addedCount ? 'success' : 'rejected');
        setDropMessage(`Добавлено: ${addedCount}. Дубликатов: ${duplicateCount}. Отклонено: ${rejected.length}.${firstReason ? ` ${firstReason}` : ''}`);
      } else {
        setDropState('success');
        setDropMessage(`Добавлено в очередь: ${addedCount}. Анализ не запущен автоматически.`);
      }
      window.setTimeout(() => setDropState('idle'), 2400);
    })().catch((reason: unknown) => {
      setDropState('rejected');
      setDropMessage(friendlyAnalysisError(reason));
    });
  }, [mode]);

  useEffect(() => {
    if (mode === 'url' || typeof window === 'undefined' || !('__TAURI_INTERNALS__' in window)) return;
    let unlisten: (() => void) | undefined;
    void getCurrentWebview().onDragDropEvent((event) => {
      const payload = event.payload;
      if (payload.type === 'leave') {
        setDropState('idle');
        return;
      }
      const inside = pointInsideDropzone(payload.position, dropzoneRef.current);
      if (payload.type === 'enter' || payload.type === 'over') {
        setDropState(inside ? 'over' : 'idle');
        if (inside) setDropMessage('Отпустите объекты, чтобы добавить их в очередь без автозапуска.');
        return;
      }
      if (payload.type === 'drop' && inside) addCandidates(payload.paths, 'drop');
    }).then((dispose) => { unlisten = dispose; });
    return () => unlisten?.();
  }, [addCandidates, mode]);

  const chooseObjects = async () => {
    setError('');
    const selected = await selectLocalObjects({ multiple: true, directory: false });
    addCandidates(selected.map((item) => item.path), 'dialog');
  };

  const enqueueUrl = () => {
    if (!url.trim() || (activeNetwork && !networkConsent)) return;
    const item = createQueueItem('url', url.trim(), urlDisplayName(url), activeNetwork);
    const appended = appendUniqueQueueItemsDetailed(queueRef.current, [item]);
    queueRef.current = appended.queue;
    setQueue(appended.queue);
    const actual = appended.added[0] ?? appended.duplicates[0]?.existing;
    if (actual) {
      manualSelectionRef.current = true;
      setSelectedId(actual.id);
      setMobilePane('details');
    }
    if (appended.duplicates.length) showQueueNotice('Объект уже находится в активной очереди. Выбрана существующая строка.');
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
    if (item.kind === 'file') return analyzeFile(item.id, item.target, limits);
    if (item.kind === 'archive') return analyzeArchive(item.id, item.target, limits);
    return item.activeNetwork
      ? analyzeUrlActive(item.id, item.target, limits)
      : analyzeUrlPassive(item.id, item.target);
  };

  const start = async () => {
    if (!canStart) return;
    let preparedQueue = queue;
    if (!pendingQueueItems(preparedQueue).length) {
      const item = currentItem();
      if (!item) return;
      const appended = appendUniqueQueueItemsDetailed(preparedQueue, [item]);
      preparedQueue = appended.queue;
      queueRef.current = preparedQueue;
      setQueue(preparedQueue);
      const actual = appended.added[0] ?? appended.duplicates[0]?.existing;
      if (actual) setSelectedId(actual.id);
    }

    const items = pendingQueueItems(preparedQueue);
    if (!items.length) return;
    stopRequestedRef.current = false;
    setRunning(true);
    setError('');

    for (const item of items) {
      if (stopRequestedRef.current) break;
      setActiveId(item.id);
      if (!manualSelectionRef.current) {
        setSelectedId(item.id);
        setMobilePane('details');
      }
      setQueue((current) => updateQueueItem(current, item.id, {
        status: 'running',
        startedAt: new Date().toISOString(),
        completedAt: undefined,
        error: undefined,
        reportId: undefined,
        riskLevel: undefined,
        riskScore: undefined,
      }));

      try {
        const result = await runItem(item);
        await saveReport(result);
        setReports((current) => ({ ...current, [result.id]: result }));
        setQueue((current) => updateQueueItem(current, item.id, {
          status: 'completed',
          completedAt: new Date().toISOString(),
          reportId: result.id,
          riskLevel: result.riskLevel,
          riskScore: result.riskScore,
        }));
        onReport?.(result);
      } catch (reason) {
        const analysisError = reason instanceof AnalysisError ? reason : null;
        if (analysisError?.code === 'cancelled') {
          setQueue((current) => confirmQueueCancellation(current, item.id));
        } else {
          const message = friendlyAnalysisError(reason);
          setQueue((current) => updateQueueItem(current, item.id, {
            status: 'failed',
            completedAt: new Date().toISOString(),
            error: message,
          }));
          setError(message);
        }
      }
      if (stopRequestedRef.current) break;
    }

    setRunning(false);
    setActiveId(null);
    stopRequestedRef.current = false;
  };

  const requestBackendCancellation = async (cancelPending: boolean) => {
    if (cancelPending) stopRequestedRef.current = true;
    setQueue((current) => cancelPending
      ? requestQueueCancellation(current, activeId)
      : activeId ? requestCurrentCancellation(current, activeId) : current);
    setError('');
    if (!activeId) {
      if (cancelPending) setRunning(false);
      return;
    }
    const accepted = await cancelAnalysis(activeId);
    if (!accepted) {
      setQueue((current) => updateQueueItem(current, activeId, { status: 'running' }));
      setError('Rust backend не нашёл активное задание для отмены. Дождитесь его завершения или повторите команду.');
      if (cancelPending) stopRequestedRef.current = false;
    }
  };

  const cancelCurrent = () => requestBackendCancellation(false);
  const cancelAll = () => requestBackendCancellation(true);

  const removeItem = (id: string) => {
    if (id === activeId) return;
    const item = queue.find((candidate) => candidate.id === id);
    setQueue((current) => current.filter((candidate) => candidate.id !== id));
    if (item?.reportId) setReports((current) => {
      const next = { ...current };
      delete next[item.reportId!];
      return next;
    });
    if (selectedId === id) {
      manualSelectionRef.current = false;
      setSelectedId(null);
    }
  };

  const retryItem = (id: string) => {
    const previous = queue.find((item) => item.id === id);
    if (!previous) return;
    const retry = createQueueItem(previous.kind, previous.target, previous.displayName, previous.activeNetwork);
    setQueue((current) => current.map((item) => item.id === id ? retry : item));
    manualSelectionRef.current = true;
    setSelectedId(retry.id);
  };

  const navigateCompleted = (offset: number) => {
    if (!completedItems.length) return;
    const current = selectedCompletedIndex >= 0 ? selectedCompletedIndex : 0;
    const next = Math.min(completedItems.length - 1, Math.max(0, current + offset));
    manualSelectionRef.current = true;
    setSelectedId(completedItems[next]?.id ?? null);
    setMobilePane('details');
  };

  const selectExplicitly = (id: string) => {
    manualSelectionRef.current = true;
    setSelectedId(id);
    setMobilePane('details');
  };

  return <div className="analysis-workspace">
    <div className="analysis-mode-tabs" role="tablist" aria-label="Тип анализа">
      <button role="tab" aria-selected={mode === 'file'} className={mode === 'file' ? 'active' : ''} onClick={() => setMode('file')}><FileSearch />Файл</button>
      <button role="tab" aria-selected={mode === 'url'} className={mode === 'url' ? 'active' : ''} onClick={() => setMode('url')}><Globe2 />URL</button>
      <button role="tab" aria-selected={mode === 'archive'} className={mode === 'archive' ? 'active' : ''} onClick={() => setMode('archive')}><Archive />ZIP-архив</button>
    </div>

    <section className="card analysis-input-card">
      <div className="card-title-row"><div><span className="analysis-kicker">FileScope Core {APP_VERSION}</span><h2>{mode === 'file' ? 'Локальный статический анализ файлов' : mode === 'archive' ? 'Безопасный просмотр ZIP-архивов' : 'Анализ URL'}</h2><p>{mode === 'url' ? 'Пассивный разбор выполняет единый Rust core. Активная сеть включается только вручную.' : 'Можно добавить 150+ объектов: очередь и отчёт прокручиваются независимо.'}</p></div><span className="badge neutral">Реальные данные</span></div>

      {mode === 'url' ? <>
        <label className="field-label" htmlFor="analysis-url">Адрес</label>
        <input id="analysis-url" className="input" value={url} onChange={(event) => { setUrl(event.target.value.trimStart()); setError(''); }} placeholder="https://example.com/path" spellCheck={false} />
        <div className="analysis-network-choice">
          <button type="button" className={`choice-card ${!activeNetwork ? 'selected' : ''}`} onClick={() => { setActiveNetwork(false); setNetworkConsent(false); }}><span><strong>Пассивный анализ</strong><small>Без DNS, HTTP и открытия страницы.</small></span></button>
          <button type="button" className={`choice-card ${activeNetwork ? 'selected' : ''}`} onClick={() => setActiveNetwork(true)}><span><strong>Ручная активная проверка</strong><small>Защищённый DNS и минимальный HEAD/Range-запрос с проверкой каждого redirect.</small></span></button>
        </div>
        {activeNetwork && <label className="consent-row analysis-consent"><input type="checkbox" checked={networkConsent} onChange={(event) => setNetworkConsent(event.target.checked)} /><span>Я понимаю, что публичный сервер увидит IP-адрес устройства. Локальные/private адреса и credentials будут заблокированы.</span></label>}
        <button className="button button-secondary analysis-enqueue" disabled={!currentInputValid || running} onClick={enqueueUrl}><Plus />Добавить URL в очередь</button>
      </> : <>
        <button
          ref={dropzoneRef}
          className={`dropzone analysis-dropzone drop-${dropState}`}
          onClick={() => void chooseObjects()}
          aria-describedby="analysis-drop-status"
        >
          {dropState === 'adding' ? <LoaderCircle className="drop-spinner" size={42} /> : <Upload size={42} />}
          <strong>{mode === 'archive' ? 'Перетащите ZIP-архивы' : 'Перетащите файлы'}</strong>
          <span>{dropMessage}</span>
          <span className="button button-primary">{mode === 'archive' ? 'Загрузить ZIP' : 'Загрузить файлы'}</span>
        </button>
        <span id="analysis-drop-status" className="sr-only" aria-live="polite">{dropMessage}</span>
      </>}

      <div className="analysis-controls">
        {!running ? <button className="button button-primary analysis-start" disabled={!canStart} onClick={() => void start()}><Play />{pendingCount > 0 ? `Запустить очередь (${pendingCount})` : 'Начать анализ'}</button> : <div className="button-row"><button className="button button-secondary" onClick={() => void cancelCurrent()}><Square />Отменить текущее</button><button className="button button-danger" onClick={() => void cancelAll()}><Square />Остановить всю очередь</button></div>}
        <span className="helper-text">Лимит файла: {Math.round(limits.maximumFileSizeBytes / 1024 / 1024)} МБ · timeout: {Math.round(limits.jobTimeoutMs / 1000)} сек.</span>
      </div>
    </section>

    {queueNotice && <section className="status-banner" role="status"><ListChecks /><div><strong>Очередь не изменена</strong><span>{queueNotice}</span></div></section>}

    {queue.length > 0 && <>
      <div className="analysis-mobile-panes" role="tablist" aria-label="Область очереди">
        <button role="tab" aria-selected={mobilePane === 'queue'} className={mobilePane === 'queue' ? 'active' : ''} onClick={() => setMobilePane('queue')}>Очередь</button>
        <button role="tab" aria-selected={mobilePane === 'details'} className={mobilePane === 'details' ? 'active' : ''} onClick={() => setMobilePane('details')}>Детали</button>
      </div>
      <section className="analysis-master-detail">
        <aside className={`card analysis-queue-pane ${mobilePane === 'queue' ? 'mobile-active' : ''}`} aria-label="Очередь проверок">
          <div className="card-title-row"><div><h2><ListChecks />Очередь</h2><p>{running && activeItem ? `Сейчас: ${activeItem.displayName}` : pendingCount ? `Ожидает запуска: ${pendingCount}` : 'Все задания обработаны.'}</p></div><strong>{finishedCount}/{queue.length}</strong></div>
          <div className="analysis-progress__track analysis-queue__progress"><span style={{ width: `${queueProgress}%` }} /></div>
          <div className="analysis-queue-filters">
            <label className="analysis-search"><Search /><input className="input" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Файл или путь" aria-label="Поиск по очереди" /></label>
            <Select label="Фильтр статуса" value={statusFilter} options={statusOptions} onChange={setStatusFilter} />
            <Select label="Фильтр риска" value={riskFilter} options={riskOptions} onChange={setRiskFilter} />
          </div>
          <VirtualQueueList
            items={filteredQueue}
            selectedId={selectedId}
            activeId={activeId}
            onSelect={selectExplicitly}
            onRemove={removeItem}
            onRetry={retryItem}
          />
          <div className="analysis-queue__footer"><span>Показано: {filteredQueue.length} из {queue.length}</span><button className="button button-secondary" disabled={running || finishedCount === 0} onClick={() => { manualSelectionRef.current = false; setQueue((current) => removeFinishedQueueItems(current)); setSelectedId(null); }}><Trash2 />Очистить завершённые</button></div>
        </aside>

        <section className={`card analysis-detail-pane ${mobilePane === 'details' ? 'mobile-active' : ''}`} aria-label="Детали выбранного задания">
          <header className="analysis-detail-toolbar">
            <div><strong>{selectedItem?.displayName ?? 'Выберите задание'}</strong><span>{selectedItem ? `${statusLabels[selectedItem.status]}${selectedItem.riskScore !== undefined ? ` · риск ${selectedItem.riskScore}/100` : ''}` : 'Очередь готова к работе'}</span></div>
            <div className="analysis-detail-navigation">
              <button className="button button-secondary" disabled={!activeId} onClick={() => { if (activeId) selectExplicitly(activeId); }}>К текущему</button>
              <button className="icon-button" aria-label="Предыдущий завершённый отчёт" disabled={!completedItems.length || selectedCompletedIndex <= 0} onClick={() => navigateCompleted(-1)}><ChevronLeft /></button>
              <span>{selectedCompletedIndex >= 0 ? `${selectedCompletedIndex + 1}/${completedItems.length}` : `0/${completedItems.length}`}</span>
              <button className="icon-button" aria-label="Следующий завершённый отчёт" disabled={!completedItems.length || selectedCompletedIndex < 0 || selectedCompletedIndex >= completedItems.length - 1} onClick={() => navigateCompleted(1)}><ChevronRight /></button>
            </div>
          </header>
          <div className="analysis-detail-scroll" ref={detailScrollRef}>
            {selectedReport ? <ReportView report={selectedReport} compact /> : <QueueItemDetails item={selectedItem} />}
          </div>
        </section>
      </section>
    </>}

    {error && <section className="status-banner warning analysis-error" role="alert"><AlertTriangle /><div><strong>Одно из заданий завершилось ошибкой</strong><span>{error}</span></div></section>}
  </div>;
}

function VirtualQueueList({ items, selectedId, activeId, onSelect, onRemove, onRetry }: {
  items: AnalysisQueueItem[];
  selectedId: string | null;
  activeId: string | null;
  onSelect: (id: string) => void;
  onRemove: (id: string) => void;
  onRetry: (id: string) => void;
}) {
  const rowHeight = 76;
  const viewportHeight = 486;
  const overscan = 5;
  const [scrollTop, setScrollTop] = useState(0);
  const start = Math.max(0, Math.floor(scrollTop / rowHeight) - overscan);
  const end = Math.min(items.length, Math.ceil((scrollTop + viewportHeight) / rowHeight) + overscan);
  return <div className="analysis-queue-viewport" style={{ height: viewportHeight }} onScroll={(event) => setScrollTop(event.currentTarget.scrollTop)}>
    <div className="analysis-queue-virtual" style={{ height: items.length * rowHeight }}>
      {items.slice(start, end).map((item, localIndex) => <QueueRow
        key={item.id}
        item={item}
        selected={item.id === selectedId}
        active={item.id === activeId}
        style={{ transform: `translateY(${(start + localIndex) * rowHeight}px)` }}
        onSelect={() => onSelect(item.id)}
        onRemove={() => onRemove(item.id)}
        onRetry={() => onRetry(item.id)}
      />)}
    </div>
  </div>;
}

function QueueRow({ item, selected, active, style, onSelect, onRemove, onRetry }: {
  item: AnalysisQueueItem;
  selected: boolean;
  active: boolean;
  style: React.CSSProperties;
  onSelect: () => void;
  onRemove: () => void;
  onRetry: () => void;
}) {
  const StatusIcon = item.status === 'completed' ? CheckCircle2 : item.status === 'failed' ? XCircle : item.status === 'running' || item.status === 'cancelling' ? LoaderCircle : item.status === 'cancelled' ? Square : Clock3;
  return <article style={style} className={`analysis-queue-item status-${item.status} ${active ? 'active' : ''} ${selected ? 'selected' : ''}`}>
    <span className="analysis-queue-item__status"><StatusIcon /></span>
    <button className="analysis-queue-item__body" onClick={onSelect}><strong>{item.displayName}</strong><span>{objectLabel(item.kind)}{item.kind === 'url' ? ` · ${item.activeNetwork ? 'активная' : 'пассивная'}` : ''} · {statusLabels[item.status]}</span>{item.riskScore !== undefined && <small className={`risk-${item.riskLevel}`}>{item.riskScore}/100</small>}{item.error && <small>{item.error}</small>}</button>
    {(item.status === 'failed' || item.status === 'cancelled') && <button className="icon-button" title="Повторить" onClick={onRetry}><RefreshCcw /></button>}
    {item.status !== 'running' && item.status !== 'cancelling' && <button className="icon-button danger" title="Убрать из очереди" onClick={onRemove}><Trash2 /></button>}
  </article>;
}

function QueueItemDetails({ item }: { item: AnalysisQueueItem | null }) {
  if (!item) return <div className="analysis-detail-empty"><ListChecks /><strong>Выберите объект в очереди</strong><span>Для завершённых заданий здесь откроется полный отчёт. Для ожидающих — текущий статус.</span></div>;
  const Icon = item.status === 'failed' ? XCircle : item.status === 'cancelled' ? Square : item.status === 'completed' ? CheckCircle2 : item.status === 'running' || item.status === 'cancelling' ? LoaderCircle : Clock3;
  return <div className={`analysis-detail-state status-${item.status}`}><Icon /><h3>{statusLabels[item.status]}</h3><p>{item.error ?? statusDescription(item.status)}</p><dl className="metadata-grid"><div><dt>Объект</dt><dd>{item.displayName}</dd></div><div><dt>Тип</dt><dd>{objectLabel(item.kind)}</dd></div><div><dt>Добавлено</dt><dd>{new Date(item.createdAt).toLocaleString('ru-RU')}</dd></div><div><dt>Job ID</dt><dd>{item.id}</dd></div></dl></div>;
}

function statusDescription(status: QueueStatus): string {
  if (status === 'pending') return 'Задание находится в очереди и ещё не обращалось к Rust backend.';
  if (status === 'running') return 'Rust backend выполняет анализ с ограничением времени, чтения и памяти.';
  if (status === 'cancelling') return 'Запрос на отмену передан backend. Статус изменится после подтверждения остановки.';
  if (status === 'cancelled') return 'Задание не завершено и не сохранено как полноценный отчёт.';
  if (status === 'failed') return 'Задание завершилось ошибкой. Техническая причина указана выше.';
  return 'Отчёт подготовлен и сохранён локально.';
}

function pointInsideDropzone(position: { x: number; y: number } | undefined, element: HTMLElement | null): boolean {
  if (!position || !element) return false;
  const rect = element.getBoundingClientRect();
  const ratio = window.devicePixelRatio || 1;
  const logicalX = position.x / ratio;
  const logicalY = position.y / ratio;
  const contains = (x: number, y: number) => x >= rect.left && x <= rect.right && y >= rect.top && y <= rect.bottom;
  return contains(logicalX, logicalY) || contains(position.x, position.y);
}

function fileName(value: string): string {
  return value.split(/[\\/]/).filter(Boolean).at(-1) ?? value;
}

function urlDisplayName(value: string): string {
  try { return new URL(value).hostname || value; } catch { return value; }
}

function objectLabel(kind: ObjectKind): string {
  return kind === 'file' ? 'Файл' : kind === 'archive' ? 'ZIP' : 'URL';
}
