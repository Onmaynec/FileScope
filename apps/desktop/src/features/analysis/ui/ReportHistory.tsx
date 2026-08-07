import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { AlertTriangle, FileJson2, LoaderCircle, Search, ShieldCheck, Trash2 } from 'lucide-react';
import { clearReportHistory, deleteReportHistory, loadReportHistory } from '../model/analysis-storage';
import type { HistoryStorageStatus, ReportHistorySnapshot } from '../model/history-repository';
import { riskLabels, type AnalysisReport, type ObjectKind, type RiskLevel } from '../model/types';
import { ReportView } from './ReportView';

export function ReportHistory() {
  const [reports, setReports] = useState<AnalysisReport[]>([]);
  const [storageStatus, setStorageStatus] = useState<HistoryStorageStatus>('ready');
  const [storageMessage, setStorageMessage] = useState('');
  const [loading, setLoading] = useState(true);
  const [query, setQuery] = useState('');
  const [kind, setKind] = useState<'all' | ObjectKind>('all');
  const [risk, setRisk] = useState<'all' | RiskLevel>('all');
  const [selected, setSelected] = useState<AnalysisReport | null>(null);
  const [clearConfirmationOpen, setClearConfirmationOpen] = useState(false);
  const cancelClearRef = useRef<HTMLButtonElement>(null);

  const applySnapshot = useCallback((snapshot: ReportHistorySnapshot) => {
    setReports(snapshot.reports);
    setStorageStatus(snapshot.status);
    setStorageMessage(snapshot.message ?? '');
  }, []);

  useEffect(() => {
    let active = true;
    void loadReportHistory().then((snapshot) => {
      if (!active) return;
      applySnapshot(snapshot);
      setLoading(false);
    });
    return () => { active = false; };
  }, [applySnapshot]);

  useEffect(() => {
    if (clearConfirmationOpen) cancelClearRef.current?.focus();
  }, [clearConfirmationOpen]);

  const filtered = useMemo(
    () => reports.filter((report) => {
      const matchesQuery = `${report.displayName} ${report.target} ${report.sha256 ?? ''}`
        .toLocaleLowerCase('ru-RU').includes(query.toLocaleLowerCase('ru-RU'));
      return matchesQuery
        && (kind === 'all' || report.objectKind === kind)
        && (risk === 'all' || report.riskLevel === risk);
    }),
    [reports, query, kind, risk],
  );

  const remove = async (id: string) => {
    const snapshot = await deleteReportHistory(id);
    applySnapshot(snapshot);
    if (snapshot.persisted && selected?.id === id) setSelected(null);
  };

  const clearHistory = async () => {
    const snapshot = await clearReportHistory();
    applySnapshot(snapshot);
    if (snapshot.persisted) {
      setSelected(null);
      setClearConfirmationOpen(false);
    }
  };

  if (selected) {
    return <div className="analysis-history">
      <button type="button" className="text-button" onClick={() => setSelected(null)}>← Вернуться к истории</button>
      <ReportView report={selected} />
    </div>;
  }

  return <div className="analysis-history">
    <section className="analysis-history__toolbar card">
      <label className="analysis-search">
        <Search />
        <input className="input" value={query} onChange={(event) => setQuery(event.target.value)}
          placeholder="Поиск по имени, пути или SHA-256" aria-label="Поиск по истории отчётов" />
      </label>
      <select className="input compact" value={kind}
        onChange={(event) => setKind(event.target.value as 'all' | ObjectKind)} aria-label="Фильтр истории по типу объекта">
        <option value="all">Все объекты</option><option value="file">Файлы</option>
        <option value="url">URL</option><option value="archive">Архивы</option>
      </select>
      <select className="input compact" value={risk}
        onChange={(event) => setRisk(event.target.value as 'all' | RiskLevel)} aria-label="Фильтр истории по уровню риска">
        <option value="all">Все уровни риска</option>
        <option value="noThreatsFound">Без обнаруженных признаков</option>
        <option value="caution">Требует внимания</option><option value="highRisk">Высокий риск</option>
        <option value="dangerous">Опасный объект</option>
      </select>
      {reports.length > 0 && <button type="button" className="button button-secondary analysis-history__clear"
        onClick={() => setClearConfirmationOpen(true)}><Trash2 />Очистить историю</button>}
    </section>

    {storageStatus !== 'ready' && storageStatus !== 'empty' && <section className="card warning-banner" role="status">
      <AlertTriangle />
      <div><strong>История открыта в защитном режиме</strong><p>{storageMessage || historyStatusMessage(storageStatus)}</p></div>
    </section>}

    {clearConfirmationOpen && <section className="analysis-history__confirmation card" role="alertdialog"
      aria-modal="true" aria-labelledby="clear-history-title" aria-describedby="clear-history-description"
      onKeyDown={(event) => { if (event.key === 'Escape') setClearConfirmationOpen(false); }}>
      <div className="analysis-history__confirmation-content">
        <strong id="clear-history-title">Очистить всю историю?</strong>
        <p id="clear-history-description">Все локально сохранённые отчёты и резервные копии миграции отчётов будут удалены без возможности восстановления. Настройки анализа останутся нетронутыми.</p>
        {storageStatus === 'unavailable' && storageMessage && <p role="status">{storageMessage}</p>}
      </div>
      <div className="analysis-history__confirmation-actions">
        <button ref={cancelClearRef} type="button" className="button button-secondary" onClick={() => setClearConfirmationOpen(false)}>Отмена</button>
        <button type="button" className="button button-danger" onClick={() => void clearHistory()}><Trash2 />Удалить все отчёты</button>
      </div>
    </section>}

    {loading ? <section className="card empty analysis-history__empty" role="status">
      <LoaderCircle className="spin" size={42} /><h2>Загрузка истории</h2><p>Проверяется версия локального storage envelope.</p>
    </section> : filtered.length === 0 ? <section className="card empty analysis-history__empty">
      <FileJson2 size={42} /><h2>{reports.length === 0 ? 'Отчётов пока нет' : 'Ничего не найдено'}</h2>
      <p>{reports.length === 0
        ? 'Выполните локальную проверку файла, URL или ZIP-архива. В v0.3.4 история проходит через совместимый repository adapter перед переносом в защищённое хранилище v0.4.0.'
        : 'Измените поисковый запрос или выбранные фильтры.'}</p>
    </section> : <section className="analysis-report-grid">
      {filtered.map((report) => <article className={`analysis-report-card risk-${report.riskLevel}`} key={report.id}>
        <button type="button" className="analysis-report-card__body" onClick={() => setSelected(report)}>
          <div className="analysis-report-card__icon"><ShieldCheck /></div>
          <div><strong>{report.displayName}</strong><span>{report.detectedType ?? report.objectKind} · {new Date(report.completedAt).toLocaleString('ru-RU')}</span>
            <b>{riskLabels[report.riskLevel]} · {report.riskScore}/100</b></div>
        </button>
        <button type="button" className="icon-button danger" onClick={() => void remove(report.id)}
          aria-label={`Удалить отчёт «${report.displayName}»`}><Trash2 /></button>
      </article>)}
    </section>}
  </div>;
}

function historyStatusMessage(status: HistoryStorageStatus): string {
  if (status === 'tooLarge') return 'История превышает безопасный лимит чтения.';
  if (status === 'unsupported') return 'История создана более новой версией FileScope и не перезаписывается.';
  if (status === 'corrupted') return 'История повреждена и сохранена без перезаписи для диагностики.';
  return 'WebView storage недоступен; текущий сеанс продолжает работать без постоянного сохранения.';
}
