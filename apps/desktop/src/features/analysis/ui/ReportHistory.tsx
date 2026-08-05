import { useMemo, useState } from 'react';
import { FileJson2, Search, ShieldCheck, Trash2 } from 'lucide-react';
import { deleteReport, loadReports } from '../model/analysis-storage';
import { riskLabels, type AnalysisReport, type ObjectKind, type RiskLevel } from '../model/types';
import { ReportView } from './ReportView';

export function ReportHistory() {
  const [reports, setReports] = useState<AnalysisReport[]>(() => loadReports());
  const [query, setQuery] = useState('');
  const [kind, setKind] = useState<'all' | ObjectKind>('all');
  const [risk, setRisk] = useState<'all' | RiskLevel>('all');
  const [selected, setSelected] = useState<AnalysisReport | null>(null);

  const filtered = useMemo(() => reports.filter((report) => {
    const matchesQuery = `${report.displayName} ${report.target} ${report.sha256 ?? ''}`.toLowerCase().includes(query.toLowerCase());
    return matchesQuery && (kind === 'all' || report.objectKind === kind) && (risk === 'all' || report.riskLevel === risk);
  }), [reports, query, kind, risk]);

  const remove = (id: string) => {
    const next = deleteReport(id);
    setReports(next);
    if (selected?.id === id) setSelected(null);
  };

  if (selected) return <div className="analysis-history"><button className="text-button" onClick={() => setSelected(null)}>← Вернуться к истории</button><ReportView report={selected} /></div>;

  return <div className="analysis-history">
    <section className="analysis-history__toolbar card">
      <div className="analysis-search"><Search /><input className="input" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Поиск по имени, пути или SHA-256" /></div>
      <select className="input compact" value={kind} onChange={(event) => setKind(event.target.value as 'all' | ObjectKind)}><option value="all">Все объекты</option><option value="file">Файлы</option><option value="url">URL</option><option value="archive">Архивы</option></select>
      <select className="input compact" value={risk} onChange={(event) => setRisk(event.target.value as 'all' | RiskLevel)}><option value="all">Все уровни риска</option><option value="noThreatsFound">Без обнаруженных признаков</option><option value="caution">Требует внимания</option><option value="highRisk">Высокий риск</option><option value="dangerous">Опасный объект</option></select>
    </section>

    {filtered.length === 0 ? <section className="card empty analysis-history__empty"><FileJson2 size={42} /><h2>Отчётов пока нет</h2><p>Выполните локальную проверку файла, URL или ZIP-архива. Результаты сохраняются только на этом устройстве.</p></section> : <section className="analysis-report-grid">{filtered.map((report) => <article className={`analysis-report-card risk-${report.riskLevel}`} key={report.id}>
      <button className="analysis-report-card__body" onClick={() => setSelected(report)}>
        <div className="analysis-report-card__icon"><ShieldCheck /></div>
        <div><strong>{report.displayName}</strong><span>{report.detectedType ?? report.objectKind} · {new Date(report.completedAt).toLocaleString('ru-RU')}</span><b>{riskLabels[report.riskLevel]} · {report.riskScore}/100</b></div>
      </button>
      <button className="icon-button danger" onClick={() => remove(report.id)} aria-label="Удалить отчёт"><Trash2 /></button>
    </article>)}</section>}
  </div>;
}
