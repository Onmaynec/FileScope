import { useEffect, useMemo, useRef, useState } from 'react';
import { AlertTriangle, Archive, FileSearch, Globe2, LoaderCircle, Play, RotateCcw, Square, Upload } from 'lucide-react';
import { selectLocalObject } from '../../../shared/native/native-bridge';
import { analyzeArchive, analyzeFile, analyzeUrlActive, analyzeUrlPassive } from '../api/analysis-api';
import { saveReport } from '../model/analysis-storage';
import type { AnalysisLimits, AnalysisReport, ObjectKind } from '../model/types';
import { ReportView } from './ReportView';

interface AnalysisWorkspaceProps {
  initialMode?: ObjectKind;
  initialPath?: string;
  limits: AnalysisLimits;
  onReport?: (report: AnalysisReport) => void;
}

const stages: Record<ObjectKind, string[]> = {
  file: ['Проверка пути и лимитов', 'Вычисление SHA-256', 'Определение фактического типа', 'Разбор PE-структуры', 'Применение правил риска'],
  url: ['Нормализация URL', 'Разбор домена и параметров', 'Поиск признаков маскировки', 'Расчёт риска'],
  archive: ['Открытие ZIP без распаковки', 'Чтение дерева записей', 'Проверка путей и лимитов', 'Поиск исполняемых объектов', 'Расчёт риска'],
};

export function AnalysisWorkspace({ initialMode = 'file', initialPath = '', limits, onReport }: AnalysisWorkspaceProps) {
  const [mode, setMode] = useState<ObjectKind>(initialMode);
  const [path, setPath] = useState(initialPath);
  const [url, setUrl] = useState('https://example.com/download?source=filescope');
  const [activeNetwork, setActiveNetwork] = useState(false);
  const [networkConsent, setNetworkConsent] = useState(false);
  const [report, setReport] = useState<AnalysisReport | null>(null);
  const [error, setError] = useState('');
  const [running, setRunning] = useState(false);
  const [cancelled, setCancelled] = useState(false);
  const [stageIndex, setStageIndex] = useState(0);
  const runToken = useRef(0);

  useEffect(() => setMode(initialMode), [initialMode]);
  useEffect(() => { if (initialPath) setPath(initialPath); }, [initialPath]);

  const currentStages = stages[mode];
  const progress = running ? Math.min(92, 8 + Math.round((stageIndex / Math.max(1, currentStages.length - 1)) * 84)) : report ? 100 : 0;
  const canStart = mode === 'url' ? Boolean(url.trim()) && (!activeNetwork || networkConsent) : Boolean(path.trim());
  const selectedLabel = useMemo(() => path.split(/[\\/]/).filter(Boolean).at(-1) ?? path, [path]);

  const chooseObject = async () => {
    setError('');
    const selected = await selectLocalObject(false);
    if (!selected) return;
    setPath(selected.path);
    setReport(null);
  };

  const start = async () => {
    if (!canStart || running) return;
    const token = ++runToken.current;
    setRunning(true);
    setCancelled(false);
    setError('');
    setReport(null);
    setStageIndex(0);
    const timer = window.setInterval(() => setStageIndex((current) => Math.min(current + 1, currentStages.length - 1)), 430);
    try {
      const result = mode === 'file'
        ? await analyzeFile(path, limits)
        : mode === 'archive'
          ? await analyzeArchive(path, limits)
          : activeNetwork
            ? await analyzeUrlActive(url, limits)
            : await analyzeUrlPassive(url);
      if (runToken.current !== token) return;
      saveReport(result);
      setReport(result);
      onReport?.(result);
    } catch (reason) {
      if (runToken.current !== token) return;
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      window.clearInterval(timer);
      if (runToken.current === token) {
        setRunning(false);
        setStageIndex(currentStages.length - 1);
      }
    }
  };

  const cancel = () => {
    runToken.current += 1;
    setRunning(false);
    setCancelled(true);
    setError('');
  };

  const reset = () => {
    runToken.current += 1;
    setRunning(false);
    setReport(null);
    setError('');
    setCancelled(false);
    setStageIndex(0);
  };

  return <div className="analysis-workspace">
    <div className="analysis-mode-tabs" role="tablist" aria-label="Тип анализа">
      <button role="tab" aria-selected={mode === 'file'} className={mode === 'file' ? 'active' : ''} onClick={() => { setMode('file'); reset(); }}><FileSearch />Файл</button>
      <button role="tab" aria-selected={mode === 'url'} className={mode === 'url' ? 'active' : ''} onClick={() => { setMode('url'); reset(); }}><Globe2 />URL</button>
      <button role="tab" aria-selected={mode === 'archive'} className={mode === 'archive' ? 'active' : ''} onClick={() => { setMode('archive'); reset(); }}><Archive />ZIP-архив</button>
    </div>

    <section className="card analysis-input-card">
      <div className="card-title-row"><div><span className="analysis-kicker">FileScope Core 0.2</span><h2>{mode === 'file' ? 'Локальный статический анализ файла' : mode === 'archive' ? 'Безопасный просмотр ZIP-архива' : 'Анализ URL'}</h2><p>{mode === 'url' ? 'Сначала выполняется пассивный разбор. Активная сеть включается только вручную.' : 'Объект не запускается, не изменяется и не отправляется во внешние сервисы.'}</p></div><span className="badge neutral">Реальные данные</span></div>

      {mode === 'url' ? <>
        <label className="field-label" htmlFor="analysis-url">Адрес</label>
        <input id="analysis-url" className="input" value={url} onChange={(event) => { setUrl(event.target.value.trimStart()); setReport(null); setError(''); }} placeholder="https://example.com/path" spellCheck={false} />
        <div className="analysis-network-choice">
          <button type="button" className={`choice-card ${!activeNetwork ? 'selected' : ''}`} onClick={() => { setActiveNetwork(false); setNetworkConsent(false); }}><span><strong>Пассивный анализ</strong><small>Без DNS, HTTP и открытия страницы.</small></span></button>
          <button type="button" className={`choice-card ${activeNetwork ? 'selected' : ''}`} onClick={() => setActiveNetwork(true)}><span><strong>Ручная активная проверка</strong><small>DNS и минимальный HEAD/Range-запрос без загрузки страницы целиком.</small></span></button>
        </div>
        {activeNetwork && <label className="consent-row analysis-consent"><input type="checkbox" checked={networkConsent} onChange={(event) => setNetworkConsent(event.target.checked)} /><span>Я понимаю, что сервер увидит IP-адрес устройства, и запускаю сетевую проверку вручную.</span></label>}
      </> : <>
        <button className="dropzone analysis-dropzone" onClick={() => void chooseObject()}>
          <Upload size={42} />
          <strong>{path ? selectedLabel : mode === 'archive' ? 'Выберите ZIP-архив' : 'Выберите файл'}</strong>
          <span>{path || (mode === 'archive' ? 'Архив читается без извлечения содержимого на диск.' : 'Поддерживается любой обычный файл; PE-файлы получают дополнительный разбор.')}</span>
          <span className="button button-primary">{path ? 'Выбрать другой объект' : 'Открыть файловый диалог'}</span>
        </button>
      </>}

      <div className="analysis-controls">
        {!running ? <button className="button button-primary analysis-start" disabled={!canStart} onClick={() => void start()}><Play />{mode === 'url' && activeNetwork ? 'Запустить активную проверку' : 'Начать анализ'}</button> : <button className="button button-danger" onClick={cancel}><Square />Отменить</button>}
        {(report || error || cancelled) && !running && <button className="button button-secondary" onClick={reset}><RotateCcw />Новая проверка</button>}
        <span className="helper-text">Лимит файла: {Math.round(limits.maximumFileSizeBytes / 1024 / 1024)} МБ</span>
      </div>
    </section>

    {(running || cancelled) && <section className="card analysis-progress" aria-live="polite">
      <div className="analysis-progress__top"><span className="analysis-progress__icon">{running ? <LoaderCircle /> : <Square />}</span><div><strong>{running ? currentStages[stageIndex] : 'Проверка отменена в интерфейсе'}</strong><span>{running ? 'Файл не запускается. Все операции выполняются с ограничениями.' : 'Поздний результат отменённого задания будет проигнорирован.'}</span></div><b>{running ? `${progress}%` : 'Остановлено'}</b></div>
      <div className="analysis-progress__track"><span style={{ width: `${running ? progress : 0}%` }} /></div>
      <ol className="analysis-stage-list">{currentStages.map((stage, index) => <li className={index < stageIndex ? 'done' : index === stageIndex && running ? 'active' : ''} key={stage}><span>{index + 1}</span>{stage}</li>)}</ol>
    </section>}

    {error && <section className="status-banner warning analysis-error" role="alert"><AlertTriangle /><div><strong>Анализ не выполнен</strong><span>{error}</span></div></section>}
    {report && <ReportView report={report} />}
  </div>;
}
